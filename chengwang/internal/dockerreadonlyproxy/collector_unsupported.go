//go:build !linux

package dockerreadonlyproxy

func NewCollector() (Collector, error) { return nil, ErrUnavailable }
