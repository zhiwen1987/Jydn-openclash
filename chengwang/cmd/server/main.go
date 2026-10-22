package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/evidence"
	"chengwang/internal/operation"
	"chengwang/internal/serverruntime"
)

const gracefulShutdownTimeout = 10 * time.Second

type runOptions struct {
	listen          func(string, string) (net.Listener, error)
	signals         <-chan os.Signal
	shutdownTimeout time.Duration
}

func main() {
	if err := run(); err != nil {
		log.Printf("chengwang stopped with error: %v", err)
		os.Exit(1)
	}
}
func run() error {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, shutdownSignals()...)
	defer signal.Stop(signals)
	return runWith(runOptions{listen: net.Listen, signals: signals, shutdownTimeout: gracefulShutdownTimeout})
}
func runWith(o runOptions) error {
	return serverruntime.RunWith(serverruntime.Options{Listen: o.listen, Signals: o.signals, ShutdownTimeout: o.shutdownTimeout})
}

// Preserve original command test pairs; every private seam delegates to the
// shared implementation rather than copying runtime logic or moving tests.
func loadTLSConfig(cert, key string) (*tls.Config, error) {
	return serverruntime.LoadTLSConfig(cert, key)
}
func listenerAddressIsLoopback(addr string) bool {
	return serverruntime.ListenerAddressIsLoopback(addr)
}
func openEvidenceStore(dir string) (*evidence.Store, error) {
	return serverruntime.OpenEvidenceStore(dir)
}
func openOperationStore(dir string) (*operation.FileStore, error) {
	return serverruntime.OpenOperationStore(dir)
}
func openIdentityStore(path string) (*authn.Store, error) {
	return serverruntime.OpenIdentityStore(path)
}
func optionalAuthenticator(s *authn.Store) api.Authenticator {
	return serverruntime.OptionalAuthenticator(s)
}
func strictBoolEnv(key string) (bool, error) { return serverruntime.StrictBoolEnv(key) }
func serveUntilShutdown(s *http.Server, l net.Listener, signals <-chan os.Signal, timeout time.Duration) error {
	return serverruntime.ServeUntilShutdown(s, l, signals, timeout)
}
