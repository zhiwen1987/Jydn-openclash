//go:build windows

package probe

// Windows has no portable directory fsync through os.File. Segment files are
// still flushed before atomic rename; Linux production additionally flushes
// the containing directory.
func syncSpoolDirectory(string) error { return nil }
