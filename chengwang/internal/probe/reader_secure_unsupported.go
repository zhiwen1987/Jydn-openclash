//go:build !linux

package probe

import "context"

// Non-Linux platforms must not silently fall back to the historical reader.
func ReadStoreSecure(context.Context, string, SecureReadOptions) (SecureReadReport, error) {
	return SecureReadReport{}, ErrSecureUnsupported
}

func ReadCatalogSecure(context.Context, string, SecureFileOwner) (Catalog, error) {
	return Catalog{}, ErrSecureUnsupported
}
