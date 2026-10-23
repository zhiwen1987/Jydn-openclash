package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// Secure readers are a new opt-in custody boundary. They do not change the
// historical ReadStore/writer contracts or acquire/create writer lock files.
// Their errors deliberately contain neither filesystem paths nor raw OS text.
var (
	ErrSecureUnsupported = errors.New("secure probe read unsupported")
	ErrSecureInvalid     = errors.New("secure probe read invalid configuration")
	ErrSecureUnsafe      = errors.New("secure probe read unsafe custody")
	ErrSecureChanged     = errors.New("secure probe read changed during observation")
	ErrSecureLimit       = errors.New("secure probe read limit exceeded")
	ErrSecureIO          = errors.New("secure probe read unavailable")
)

type SecureFileOwner struct {
	UID uint32
	GID uint32
}

type SecureReadOptions struct {
	ReadOptions
	OwnerUID uint32
	OwnerGID uint32
}

// ValidTotal counts content-valid unique results, including expired results.
// ExpiredTotal is the expired subset; normal expiry is not corrupt content.
// EligibleTotal applies IncludeExpired before the global newest-result limit.
// Counts describing semantic eligibility are complete only on a nil error.
// On error Results is always nil, Healthy is false, and physical scan counters
// describe only work actually performed, not an inferred directory total.
type SecureReadReport struct {
	ReadReport
	ScannedEntries int
	ValidTotal     int
	ExpiredTotal   int
	EligibleTotal  int
	Returned       int
	Truncated      bool
}

func secureContext(ctx context.Context) error {
	if ctx == nil {
		return ErrSecureInvalid
	}
	return ctx.Err()
}

func securePathParts(path string) ([]string, error) {
	if path == "" || len(path) > 4096 || strings.TrimSpace(path) != path ||
		strings.ContainsAny(path, "\x00\\") || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrSecureInvalid
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 1 || len(parts) > 64 {
		return nil, ErrSecureInvalid
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return nil, ErrSecureInvalid
		}
	}
	return parts, nil
}

func secureOptions(ctx context.Context, options SecureReadOptions) (SecureReadOptions, catalogBinding, error) {
	if err := secureContext(ctx); err != nil {
		return options, catalogBinding{}, err
	}
	if options.Limit == 0 {
		options.Limit = defaultReadResults
	}
	if options.Limit < 1 || options.Limit > MaximumReadResults {
		return options, catalogBinding{}, ErrSecureInvalid
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.MaxFutureSkew == 0 {
		options.MaxFutureSkew = defaultFutureSkew
	}
	if options.MaxFutureSkew < 0 || options.MaxFutureSkew > 10*time.Minute {
		return options, catalogBinding{}, ErrSecureInvalid
	}
	entries, size, err := normalizeSpoolLimits(options.MaxEntries, options.MaxBytes)
	if err != nil {
		return options, catalogBinding{}, ErrSecureInvalid
	}
	options.MaxEntries, options.MaxBytes = entries, size
	binding, err := bindCatalog(options.Catalog)
	if err != nil {
		return options, catalogBinding{}, ErrSecureInvalid
	}
	if err := secureContext(ctx); err != nil {
		return options, catalogBinding{}, err
	}
	return options, binding, nil
}

// This decoder reuses the pre-existing pure semantic validators, but never the
// old path-opening reader. Expiry is counted separately by the secure reader.
func decodeSecureSegment(raw []byte, binding catalogBinding, now time.Time, futureSkew time.Duration) (spoolSegment, string) {
	if len(raw) == 0 || int64(len(raw)) > MaximumSpoolSegmentBytes {
		return spoolSegment{}, "segment_size_invalid"
	}
	if rejectDuplicateJSONKeys(raw) != nil {
		return spoolSegment{}, "segment_json_duplicate_key"
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var segment spoolSegment
	if decoder.Decode(&segment) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return spoolSegment{}, "segment_json_invalid"
	}
	if segment.Schema != SpoolSchemaV1 {
		return spoolSegment{}, "unknown_schema"
	}
	if segment.CatalogDigest != binding.digest || segment.Result.CatalogDigest != binding.digest {
		return spoolSegment{}, "catalog_digest_mismatch"
	}
	digest, err := spoolContentDigest(segment.Schema, segment.CatalogDigest, segment.Result)
	if err != nil || segment.Digest != digest {
		return spoolSegment{}, "content_digest_mismatch"
	}
	if reason := validateSpoolResult(segment.Result, binding, now, futureSkew, true, false); reason != "" {
		return spoolSegment{}, reason
	}
	return segment, ""
}
