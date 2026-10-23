//go:build !linux

package subscription

// Private admission persistence currently requires the native Linux custody
// and process-lock implementation. There is no unsafe portable fallback.
func storeOpenDisk(string) (storeDiskIO, error) { return nil, fail(CodeStoreUnsafe) }
