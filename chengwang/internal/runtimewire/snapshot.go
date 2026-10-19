// Package runtimewire defines the deliberately small, secret-free wire
// contract between the privileged Docker collector and the unprivileged
// restore runtime observer.
package runtimewire

const SchemaV1 = "chengwang.docker-runtime-snapshot/v1"

type Snapshot struct {
	Schema      string    `json:"schema"`
	ProjectName string    `json:"projectName"`
	ServiceName string    `json:"serviceName"`
	Container   Container `json:"container"`
	Image       Image     `json:"image"`
	Network     Network   `json:"network"`
}

type Container struct {
	ID                string   `json:"id"`
	ImageID           string   `json:"imageId"`
	ImageReference    string   `json:"imageReference"`
	Name              string   `json:"name"`
	Status            string   `json:"status"`
	HealthStatus      string   `json:"healthStatus"`
	StartedAt         string   `json:"startedAt"`
	Running           bool     `json:"running"`
	Paused            bool     `json:"paused"`
	Restarting        bool     `json:"restarting"`
	OOMKilled         bool     `json:"oomKilled"`
	Dead              bool     `json:"dead"`
	PID               int      `json:"pid"`
	ProcessStartTicks uint64   `json:"processStartTicks"`
	NetNSDevice       uint64   `json:"netnsDevice"`
	NetNSInode        uint64   `json:"netnsInode"`
	RestartCount      int      `json:"restartCount"`
	User              string   `json:"user"`
	ReadOnlyRootFS    bool     `json:"readOnlyRootFs"`
	Privileged        bool     `json:"privileged"`
	Init              bool     `json:"init"`
	TTY               bool     `json:"tty"`
	OpenStdin         bool     `json:"openStdin"`
	CapDrop           []string `json:"capDrop"`
	SecurityOpt       []string `json:"securityOpt"`
	PidsLimit         int64    `json:"pidsLimit"`
	MemoryBytes       int64    `json:"memoryBytes"`
	ReservationBytes  int64    `json:"reservationBytes"`
	NanoCPUs          int64    `json:"nanoCpus"`
	RestartPolicy     string   `json:"restartPolicy"`
	NetworkMode       string   `json:"networkMode"`
	Mounts            []Mount  `json:"mounts"`
	Tmpfs             []string `json:"tmpfs"`
}

type Mount struct {
	Type        string `json:"type"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"readOnly"`
}

type Image struct {
	ID string `json:"id"`
}

type Network struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	Driver     string `json:"driver"`
	Internal   bool   `json:"internal"`
	Attachable bool   `json:"attachable"`
	SandboxID  string `json:"sandboxId"`
}
