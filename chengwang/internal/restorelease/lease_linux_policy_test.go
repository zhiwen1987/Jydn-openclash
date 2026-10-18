//go:build linux

package restorelease

import "testing"

func TestProductionCandidatePathPolicy(t *testing.T) {
	for _, path := range []string{
		"relative", "/tmp/probe", "/var/lib/chengwang-m2b-candidate", "/var/lib/chengwang-m2b-candidate/UPPER", "/var/lib/chengwang-m2b-candidate/two/levels", "/var/lib/chengwang-m2b-candidate/trailing/",
	} {
		if _, err := productionBase(path); err == nil {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	for _, path := range []string{"/var/lib/chengwang-m2b-candidate/probe-1", "/srv/chengwang-m2b-candidate/a_2"} {
		if _, err := productionBase(path); err != nil {
			t.Fatalf("safe path rejected: %q: %v", path, err)
		}
	}
}
