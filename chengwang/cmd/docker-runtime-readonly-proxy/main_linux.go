//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"chengwang/internal/dockerreadonlyproxy"
)

const (
	frontendDirectory = "/run/chengwang-runtime-observer"
	frontendSocket    = "/run/chengwang-runtime-observer/readonly.sock"
	observerGroup     = "chengwang-runtime-observer"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	group, err := user.LookupGroup(observerGroup)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid <= 0 {
		return errors.New("observer group is invalid")
	}
	if err := validateFrontendDirectory(gid); err != nil {
		return err
	}
	if _, err := os.Lstat(frontendSocket); !errors.Is(err, os.ErrNotExist) {
		return errors.New("front-end socket path must not exist")
	}
	collector, err := dockerreadonlyproxy.NewCollector()
	if err != nil {
		return err
	}
	handler, err := dockerreadonlyproxy.NewServer(collector)
	if err != nil {
		return err
	}
	listener, err := net.Listen("unix", frontendSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(frontendSocket, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(frontendSocket, 0660); err != nil {
		return err
	}
	identity, err := socketIdentity(frontendSocket)
	if err != nil {
		return err
	}
	defer removeOwnSocket(identity)

	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	stopContext, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-stopContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	}
}

func validateFrontendDirectory(gid int) error {
	if filepath.Clean(frontendDirectory) != frontendDirectory || filepath.Dir(frontendSocket) != frontendDirectory {
		return errors.New("front-end path contract is invalid")
	}
	info, err := os.Lstat(frontendDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 {
		return errors.New("front-end directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || int(stat.Gid) != gid {
		return errors.New("front-end directory ownership is unsafe")
	}
	return nil
}

type fileIdentity struct{ device, inode uint64 }

func socketIdentity(path string) (fileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return fileIdentity{}, errors.New("front-end socket is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return fileIdentity{}, errors.New("front-end socket identity is unavailable")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func removeOwnSocket(wanted fileIdentity) {
	current, err := socketIdentity(frontendSocket)
	if err == nil && current == wanted {
		_ = os.Remove(frontendSocket)
	}
}
