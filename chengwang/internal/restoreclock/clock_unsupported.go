//go:build !linux

package restoreclock

func platformSample() (rawSample, error) {
	return rawSample{}, ErrUnsupported
}
