//go:build linux

package dockerreadonlyproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"chengwang/internal/runtimewire"
)

const (
	dockerSocketPath  = "/run/docker.sock"
	dockerAPIPrefix   = "/v1.45"
	maximumDockerJSON = 2 << 20
)

type dockerCollector struct{ client *http.Client }

func NewCollector() (Collector, error) {
	if err := validateDockerSocket(dockerSocketPath); err != nil {
		return nil, ErrUnavailable
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", dockerSocketPath)
		},
	}
	return &dockerCollector{client: &http.Client{
		Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func validateDockerSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return ErrUnavailable
	}
	return nil
}

type containerListEntry struct {
	ID      string            `json:"Id"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
}

type containerInspect struct {
	ID           string `json:"Id"`
	Image        string `json:"Image"`
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		Dead       bool   `json:"Dead"`
		PID        int    `json:"Pid"`
		StartedAt  string `json:"StartedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image     string            `json:"Image"`
		User      string            `json:"User"`
		Labels    map[string]string `json:"Labels"`
		TTY       bool              `json:"Tty"`
		OpenStdin bool              `json:"OpenStdin"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs    bool              `json:"ReadonlyRootfs"`
		Privileged        bool              `json:"Privileged"`
		Init              *bool             `json:"Init"`
		CapDrop           []string          `json:"CapDrop"`
		SecurityOpt       []string          `json:"SecurityOpt"`
		PidsLimit         int64             `json:"PidsLimit"`
		Memory            int64             `json:"Memory"`
		MemoryReservation int64             `json:"MemoryReservation"`
		NanoCPUs          int64             `json:"NanoCpus"`
		NetworkMode       string            `json:"NetworkMode"`
		Tmpfs             map[string]string `json:"Tmpfs"`
		RestartPolicy     struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		SandboxID string `json:"SandboxID"`
		Networks  map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type imageInspect struct {
	ID string `json:"Id"`
}

type networkInspect struct {
	Name       string `json:"Name"`
	ID         string `json:"Id"`
	Driver     string `json:"Driver"`
	Internal   bool   `json:"Internal"`
	Attachable bool   `json:"Attachable"`
}

func (collector *dockerCollector) Snapshot(ctx context.Context, project string) (runtimewire.Snapshot, error) {
	if collector == nil || collector.client == nil || !projectPattern.MatchString(project) {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	containerID, imageID, err := collector.uniqueContainer(ctx, project)
	if err != nil {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	first, err := collector.inspectContainer(ctx, containerID)
	if err != nil || first.ID != containerID || first.Image != imageID {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	process, err := readProcessIdentity(first.State.PID)
	if err != nil {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	image, err := collector.inspectImage(ctx, imageID)
	if err != nil || image.ID != imageID {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	networkName, networkID, err := exactContainerNetwork(first)
	if err != nil {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	network, err := collector.inspectNetwork(ctx, networkID)
	if err != nil || network.ID != networkID || network.Name != networkName {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	second, err := collector.inspectContainer(ctx, containerID)
	if err != nil {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	secondProcess, err := readProcessIdentity(second.State.PID)
	if err != nil || !stableContainer(first, second) || process != secondProcess {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	if !labelsMatch(second.Config.Labels, project) {
		return runtimewire.Snapshot{}, ErrUnavailable
	}
	snapshot := projectSnapshot(project, second, image, network, process)
	return snapshot, nil
}

type processIdentity struct {
	startTicks uint64
	netDevice  uint64
	netInode   uint64
}

func readProcessIdentity(pid int) (processIdentity, error) {
	if pid <= 0 {
		return processIdentity{}, ErrUnavailable
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return processIdentity{}, ErrUnavailable
	}
	defer clear(raw)
	closing := bytes.LastIndexByte(raw, ')')
	if closing < 1 || closing+2 >= len(raw) {
		return processIdentity{}, ErrUnavailable
	}
	fields := strings.Fields(string(raw[closing+2:]))
	if len(fields) <= 19 {
		return processIdentity{}, ErrUnavailable
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return processIdentity{}, ErrUnavailable
	}
	info, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/ns/net")
	if err != nil {
		return processIdentity{}, ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return processIdentity{}, ErrUnavailable
	}
	return processIdentity{startTicks: startTicks, netDevice: uint64(stat.Dev), netInode: stat.Ino}, nil
}

func (collector *dockerCollector) uniqueContainer(ctx context.Context, project string) (string, string, error) {
	filter := map[string][]string{"label": {
		"com.docker.compose.project=" + project,
		"com.docker.compose.service=probe-agent",
		"com.jydn.chengwang.component=m2b-probe-agent-candidate",
		"com.jydn.chengwang.active-probes=true",
		"com.jydn.chengwang.advisory-only=true",
		"com.jydn.chengwang.egress-approved=false",
	}}
	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return "", "", ErrUnavailable
	}
	query := url.Values{"all": {"1"}, "filters": {string(filterJSON)}}.Encode()
	var values []containerListEntry
	if err := collector.getJSON(ctx, dockerAPIPrefix+"/containers/json?"+query, &values); err != nil || len(values) != 1 {
		return "", "", ErrUnavailable
	}
	value := values[0]
	if !fullContainerID(value.ID) || !fullImageID(value.ImageID) || value.State != "running" || !labelsMatch(value.Labels, project) {
		return "", "", ErrUnavailable
	}
	return value.ID, value.ImageID, nil
}

func (collector *dockerCollector) inspectContainer(ctx context.Context, id string) (containerInspect, error) {
	if !fullContainerID(id) {
		return containerInspect{}, ErrUnavailable
	}
	var value containerInspect
	if err := collector.getJSON(ctx, dockerAPIPrefix+"/containers/"+id+"/json", &value); err != nil {
		return containerInspect{}, err
	}
	return value, nil
}

func (collector *dockerCollector) inspectImage(ctx context.Context, id string) (imageInspect, error) {
	if !fullImageID(id) {
		return imageInspect{}, ErrUnavailable
	}
	var value imageInspect
	if err := collector.getJSON(ctx, dockerAPIPrefix+"/images/"+id+"/json", &value); err != nil {
		return imageInspect{}, err
	}
	return value, nil
}

func (collector *dockerCollector) inspectNetwork(ctx context.Context, id string) (networkInspect, error) {
	if !fullContainerID(id) {
		return networkInspect{}, ErrUnavailable
	}
	var value networkInspect
	if err := collector.getJSON(ctx, dockerAPIPrefix+"/networks/"+id, &value); err != nil {
		return networkInspect{}, err
	}
	return value, nil
}

func (collector *dockerCollector) getJSON(ctx context.Context, requestPath string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+requestPath, nil)
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := collector.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumDockerJSON+1))
	if err != nil || len(body) == 0 || len(body) > maximumDockerJSON {
		clear(body)
		return ErrUnavailable
	}
	defer clear(body)
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrUnavailable
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrUnavailable
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrUnavailable
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrUnavailable
	}
	_, err = decoder.Token()
	return err
}

func labelsMatch(labels map[string]string, project string) bool {
	return labels["com.docker.compose.project"] == project &&
		labels["com.docker.compose.service"] == "probe-agent" &&
		labels["com.jydn.chengwang.component"] == "m2b-probe-agent-candidate" &&
		labels["com.jydn.chengwang.active-probes"] == "true" &&
		labels["com.jydn.chengwang.advisory-only"] == "true" &&
		labels["com.jydn.chengwang.egress-approved"] == "false"
}

func fullContainerID(value string) bool { return lowerHex(value, 64) }
func fullImageID(value string) bool {
	return strings.HasPrefix(value, "sha256:") && lowerHex(strings.TrimPrefix(value, "sha256:"), 64)
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func exactContainerNetwork(value containerInspect) (string, string, error) {
	if len(value.NetworkSettings.Networks) != 1 {
		return "", "", ErrUnavailable
	}
	for name, attachment := range value.NetworkSettings.Networks {
		if name == "" || !fullContainerID(attachment.NetworkID) {
			return "", "", ErrUnavailable
		}
		return name, attachment.NetworkID, nil
	}
	return "", "", ErrUnavailable
}

func stableContainer(first, second containerInspect) bool {
	firstNetworkName, firstNetworkID, firstErr := exactContainerNetwork(first)
	secondNetworkName, secondNetworkID, secondErr := exactContainerNetwork(second)
	return firstErr == nil && secondErr == nil && first.ID == second.ID && first.Image == second.Image &&
		first.State.PID == second.State.PID && first.State.StartedAt == second.State.StartedAt &&
		first.RestartCount == second.RestartCount && first.State.Running == second.State.Running &&
		first.State.Paused == second.State.Paused && first.State.Restarting == second.State.Restarting &&
		first.State.OOMKilled == second.State.OOMKilled && first.State.Dead == second.State.Dead &&
		firstNetworkName == secondNetworkName && firstNetworkID == secondNetworkID
}

func projectSnapshot(project string, container containerInspect, image imageInspect, network networkInspect, process processIdentity) runtimewire.Snapshot {
	mounts := make([]runtimewire.Mount, 0, len(container.Mounts))
	for _, mount := range container.Mounts {
		mounts = append(mounts, runtimewire.Mount{Type: mount.Type, Destination: mount.Destination, ReadOnly: !mount.RW})
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Destination < mounts[j].Destination })
	tmpfs := make([]string, 0, len(container.HostConfig.Tmpfs))
	for destination, options := range container.HostConfig.Tmpfs {
		tmpfs = append(tmpfs, destination+":"+options)
	}
	sort.Strings(tmpfs)
	health := "missing"
	if container.State.Health != nil {
		health = container.State.Health.Status
	}
	networkName, _, _ := exactContainerNetwork(container)
	init := container.HostConfig.Init != nil && *container.HostConfig.Init
	return runtimewire.Snapshot{
		Schema: runtimewire.SchemaV1, ProjectName: project, ServiceName: "probe-agent",
		Container: runtimewire.Container{
			ID: container.ID, ImageID: container.Image, ImageReference: container.Config.Image,
			Name: strings.TrimPrefix(container.Name, "/"), Status: container.State.Status,
			HealthStatus: health, StartedAt: container.State.StartedAt, Running: container.State.Running,
			Paused: container.State.Paused, Restarting: container.State.Restarting, OOMKilled: container.State.OOMKilled,
			Dead: container.State.Dead, PID: container.State.PID, ProcessStartTicks: process.startTicks,
			NetNSDevice: process.netDevice, NetNSInode: process.netInode, RestartCount: container.RestartCount,
			User: container.Config.User, ReadOnlyRootFS: container.HostConfig.ReadonlyRootfs,
			Privileged: container.HostConfig.Privileged, Init: init, TTY: container.Config.TTY,
			OpenStdin: container.Config.OpenStdin, CapDrop: sortedCopy(container.HostConfig.CapDrop),
			SecurityOpt: sortedCopy(container.HostConfig.SecurityOpt), PidsLimit: container.HostConfig.PidsLimit,
			MemoryBytes: container.HostConfig.Memory, ReservationBytes: container.HostConfig.MemoryReservation,
			NanoCPUs: container.HostConfig.NanoCPUs, RestartPolicy: container.HostConfig.RestartPolicy.Name,
			NetworkMode: container.HostConfig.NetworkMode, Mounts: mounts, Tmpfs: tmpfs,
		},
		Image: runtimewire.Image{ID: image.ID},
		Network: runtimewire.Network{Name: networkName, ID: network.ID, Driver: network.Driver,
			Internal: network.Internal, Attachable: network.Attachable, SandboxID: container.NetworkSettings.SandboxID},
	}
}

func sortedCopy(values []string) []string {
	copy := append([]string(nil), values...)
	sort.Strings(copy)
	return copy
}
