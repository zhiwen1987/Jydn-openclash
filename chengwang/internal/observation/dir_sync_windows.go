//go:build windows

package observation

// Windows does not expose a portable directory fsync through os.File. Segment
// files are still flushed before atomic rename; Linux production additionally
// flushes the containing directory.
func syncDirectory(string) error { return nil }
