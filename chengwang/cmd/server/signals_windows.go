//go:build windows

package main

import "os"

func shutdownSignals() []os.Signal {
	// Windows has no native SIGTERM delivery. os.Interrupt keeps Ctrl+C
	// graceful, while service managers should send an interrupt or stop the
	// container, which Docker translates for the Linux production image.
	return []os.Signal{os.Interrupt}
}
