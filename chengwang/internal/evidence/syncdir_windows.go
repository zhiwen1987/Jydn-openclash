//go:build windows

package evidence

// Go's os.File.Sync is not supported for directory handles on Windows. The
// checkpoint file itself is flushed before the atomic rename; there is no
// portable directory-flush primitive to add here. A caller still gets the
// same fail-closed behavior if any preceding checkpoint step fails.
func syncDirectory(string) error {
	return nil
}
