//go:build !linux

package subscriptionpolicy

import "context"

// No os.ReadFile fallback is permitted on unsupported platforms.
func LoadSecure(context.Context, string, Owner) (*Catalog, error) {
	return nil, ErrUnsupported
}
