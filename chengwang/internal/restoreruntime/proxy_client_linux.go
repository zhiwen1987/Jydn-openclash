//go:build linux

package restoreruntime

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"chengwang/internal/dockerreadonlyproxy"
	"chengwang/internal/runtimewire"
)

const readonlyProxySocket = "/run/chengwang-runtime-observer/readonly.sock"

type proxyClient struct{ client *http.Client }

func productionClient() (snapshotClient, error) {
	identity, err := proxySocketIdentity(readonlyProxySocket)
	if err != nil {
		return nil, ErrUnsupported
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			before, err := proxySocketIdentity(readonlyProxySocket)
			if err != nil || before != identity {
				return nil, ErrUnstable
			}
			connection, err := dialer.DialContext(ctx, "unix", readonlyProxySocket)
			if err != nil {
				return nil, ErrUnsupported
			}
			if err := verifyPeerRoot(connection); err != nil {
				connection.Close()
				return nil, ErrUnsupported
			}
			after, err := proxySocketIdentity(readonlyProxySocket)
			if err != nil || after != identity {
				connection.Close()
				return nil, ErrUnstable
			}
			return connection, nil
		},
	}
	return &proxyClient{client: &http.Client{
		Transport: transport, Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

type socketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
}

func proxySocketIdentity(path string) (socketIdentity, error) {
	if path != readonlyProxySocket || filepath.Clean(path) != path {
		return socketIdentity{}, ErrUnsupported
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0022 != 0 {
		return socketIdentity{}, ErrUnsupported
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 {
		return socketIdentity{}, ErrUnsupported
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0007 != 0 {
		return socketIdentity{}, ErrUnsupported
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || stat.Ino == 0 {
		return socketIdentity{}, ErrUnsupported
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid, gid: stat.Gid}, nil
}

func verifyPeerRoot(connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrUnsupported
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrUnsupported
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil || credentials == nil || credentials.Uid != 0 || credentials.Pid <= 0 {
		return ErrUnsupported
	}
	return nil
}

func (client *proxyClient) Snapshot(ctx context.Context, project string) (runtimewire.Snapshot, error) {
	if client == nil || client.client == nil || ctx == nil {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	requestPath := dockerreadonlyproxy.SnapshotPathPrefix + url.PathEscape(project) + "/probe-agent"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://runtime"+requestPath, nil)
	if err != nil {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return runtimewire.Snapshot{}, ErrUnsupported
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" ||
		response.Header.Get("Content-Type") != "application/json" {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumSnapshotBytes+1))
	if err != nil || len(raw) > maximumSnapshotBytes {
		clear(raw)
		return runtimewire.Snapshot{}, ErrInvalid
	}
	defer clear(raw)
	return decodeSnapshot(raw)
}
