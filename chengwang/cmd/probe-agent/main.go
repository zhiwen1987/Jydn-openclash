package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func execute(ctx context.Context, args []string, stderr io.Writer) error {
	if ctx == nil {
		return errors.New("probe-agent context is nil")
	}
	if len(args) > 0 && args[0] == "health" {
		return runHealthCommand(args[1:], stderr, time.Now)
	}
	value, err := parseConfig(args, stderr)
	if err != nil {
		return err
	}
	app, err := newApplication(value)
	if err != nil {
		return err
	}
	return app.run(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Print(fmt.Errorf("probe-agent: %w", err))
		os.Exit(1)
	}
}
