//go:build !linux

package mihomodeploy

type labDiagnosticsPlatform struct{}

func openLabDiagnosticsPlatform() (*labDiagnosticsPlatform, error) { return nil, errLabDiagnostics }
func (*labDiagnosticsPlatform) write(string, []byte, bool) error   { return errLabDiagnostics }
func (*labDiagnosticsPlatform) close() error                       { return nil }
func labServiceEnvelope() error                                    { return errLabKernelUnsupported }
func labServiceKernelStreams(*ownedLabKernel) ([]byte, []byte, error) {
	return nil, nil, errLabKernelUnsupported
}
