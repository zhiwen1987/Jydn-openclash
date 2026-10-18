//go:build !windows

package probe

import (
	"fmt"
	"os"
)

func syncSpoolDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open probe spool directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync probe spool directory: %w", err)
	}
	return nil
}
