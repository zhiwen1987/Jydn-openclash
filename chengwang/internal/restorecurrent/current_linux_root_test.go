//go:build linux && restorecurrent_root

package restorecurrent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"

	"chengwang/internal/restorelease"
)

const candidateMarker = "chengwang-m2b-candidate-root/v1\n"

func TestLinuxAdvisoryCollectorReturnsBlockedWithoutAuthoritativeState(t *testing.T) {
	root, contents := resetLinuxCandidate(t)
	handle, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	observation, err := handle.Observation()
	if err != nil {
		t.Fatal(err)
	}
	if observation.Schema() != ObservationSchemaV1 || observation.Authorization() != "BLOCKED" || observation.CandidateRoot() != root || observation.ServiceName() != serviceName || observation.StateMountTarget() != stateMountTarget || observation.BootID() == "" || observation.ObservedUnix() <= 0 || observation.ObservedBoottimeNS() == 0 {
		t.Fatalf("invalid blocked observation: %#v", observation)
	}
	if !reflect.DeepEqual(observation.Blockers(), sortedMandatoryBlockers()) {
		t.Fatalf("blockers=%v", observation.Blockers())
	}
	digests := observation.Configuration()
	if digests.ProbeEnvSHA256 != digest(contents.env) || digests.CatalogSHA256 != digest(contents.catalog) || digests.DotCASHA256 != digest(contents.ca) || digests.EgressPolicySHA256 != digest(contents.policy) || !strings.HasPrefix(digests.CatalogDigest, "sha256:") {
		t.Fatalf("configuration digests are not bound to raw held bytes: %#v", digests)
	}
	if err := handle.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxIdentityBoundObservationKeepsAllTrustBlockers(t *testing.T) {
	root, contents := resetLinuxCandidate(t)
	handle, err := OpenIdentityBound(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	observation, err := handle.Observation()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseCandidateIdentity(contents.identity, root, observation.Instance(), observation.ProjectName())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Schema() != IdentityObservationSchemaV1 || observation.Boundary() != "ADVISORY_LOCAL_IDENTITY_BOUND" || observation.Authorization() != "BLOCKED" || observation.CandidateID() != identity.CandidateID || observation.IdentityGeneration() != 1 || observation.IdentitySHA256() != digest(contents.identity) {
		t.Fatalf("invalid identity-bound observation: %#v", observation)
	}
	if !reflect.DeepEqual(observation.Blockers(), sortedMandatoryBlockers()) {
		t.Fatalf("identity blockers=%v", observation.Blockers())
	}
}

func TestLinuxIdentityBoundDetectsIdentityMutationAndPoisons(t *testing.T) {
	mutations := map[string]func(*testing.T, string, configurationContents){
		"path-replacement": func(t *testing.T, path string, contents configurationContents) {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			writeExact(t, path, contents.identity, 0, 10001, 0o640)
		},
		"in-place-mutation": func(t *testing.T, path string, _ configurationContents) {
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt([]byte("["), 0); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		},
		"unlink": func(t *testing.T, path string, _ configurationContents) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"oversize": func(t *testing.T, path string, _ configurationContents) {
			if err := os.Truncate(path, int64(maxCandidateIdentityBytes+1)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			root, contents := resetLinuxCandidate(t)
			handle, err := OpenIdentityBound(root)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			identityPath := filepath.Join(root, "config", candidateIdentityFileSpec.name)
			mutate(t, identityPath, contents)
			if err := handle.Verify(); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("Verify error=%v, want ErrPoisoned", err)
			}
			if _, err := handle.Observation(); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("Observation error=%v, want sticky ErrPoisoned", err)
			}
		})
	}
}

func TestLinuxIdentityBoundRejectsUnsafeIdentityObjects(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, root string) {
			path := filepath.Join(root, "config", candidateIdentityFileSpec.name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("catalog.json", path); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, root string) {
			path := filepath.Join(root, "config", candidateIdentityFileSpec.name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(root, "config", "catalog.json"), path); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, root string) {
			path := filepath.Join(root, "config", candidateIdentityFileSpec.name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 0, 10001); err != nil {
				t.Fatal(err)
			}
		},
		"empty": func(t *testing.T, root string) {
			writeExact(t, filepath.Join(root, "config", candidateIdentityFileSpec.name), nil, 0, 10001, 0o640)
		},
		"wrong-mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config", candidateIdentityFileSpec.name), 0o660); err != nil {
				t.Fatal(err)
			}
		},
		"special-mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config", candidateIdentityFileSpec.name), os.ModeSetuid|0o640); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-owner": func(t *testing.T, root string) {
			if err := os.Chown(filepath.Join(root, "config", candidateIdentityFileSpec.name), 10001, 10001); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root, _ := resetLinuxCandidate(t)
			mutate(t, root)
			if handle, err := OpenIdentityBound(root); err == nil {
				handle.Close()
				t.Fatal("unsafe candidate identity was accepted")
			}
			lease, err := restorelease.Acquire(root)
			if err != nil {
				t.Fatalf("failed construction leaked lifecycle lease: %v", err)
			}
			lease.Close()
		})
	}
}

func TestLinuxAdvisoryCollectorExcludesConcurrentLifecycleAndReopens(t *testing.T) {
	root, _ := resetLinuxCandidate(t)
	first, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAdvisory(root); !errors.Is(err, restorelease.ErrBusy) {
		t.Fatalf("second collector error=%v, want restorelease.ErrBusy", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxAdvisoryCollectorDetectsConfigurationMutationAndPoisons(t *testing.T) {
	root, contents := resetLinuxCandidate(t)
	handle, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	path := filepath.Join(root, "config", "catalog.json")
	mutated := append([]byte(nil), contents.catalog...)
	mutated[len(mutated)/2] ^= 1
	writeExact(t, path, mutated, 0, 10001, 0o640)
	if err := handle.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("Verify error=%v, want ErrPoisoned", err)
	}
	if _, err := handle.Observation(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("Observation error=%v, want sticky ErrPoisoned", err)
	}
}

func TestLinuxAdvisoryCollectorDetectsFileAndDirectoryReplacement(t *testing.T) {
	for _, target := range []string{"probe.env", "catalog.json", "dot-ca.pem", "egress-policy.json", "config"} {
		t.Run(target, func(t *testing.T) {
			root, contents := resetLinuxCandidate(t)
			handle, err := OpenAdvisory(root)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			config := filepath.Join(root, "config")
			if target != "config" {
				original := filepath.Join(config, target)
				if err := os.Rename(original, original+".old"); err != nil {
					t.Fatal(err)
				}
				spec, raw := fileFixture(target, contents)
				writeExact(t, original, raw, int(spec.uid), int(spec.gid), os.FileMode(spec.mode))
			} else {
				if err := os.Rename(config, config+".old"); err != nil {
					t.Fatal(err)
				}
				writeConfigTree(t, config, contents)
			}
			if err := handle.Verify(); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("Verify error=%v, want ErrPoisoned", err)
			}
		})
	}
}

func TestLinuxAdvisoryCollectorDetectsCandidateRootReplacement(t *testing.T) {
	root, contents := resetLinuxCandidate(t)
	handle, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	old := root + ".old"
	t.Cleanup(func() { cleanupOwnedTestRoot(t, old) })
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExact(t, filepath.Join(root, ".chengwang-m2b-candidate-root"), []byte(candidateMarker), 0, 0, 0o600)
	writeConfigTree(t, filepath.Join(root, "config"), contents)
	if err := handle.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("Verify error=%v, want ErrPoisoned", err)
	}
}

func TestLinuxAdvisoryCollectorRejectsUnsafeConfigObjects(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"config-symlink": func(t *testing.T, root string) {
			config := filepath.Join(root, "config")
			if err := os.Rename(config, config+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("config.old", config); err != nil {
				t.Fatal(err)
			}
		},
		"config-wrong-owner": func(t *testing.T, root string) {
			config := filepath.Join(root, "config")
			if err := os.Chown(config, 10001, 10001); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				info, err := os.Lstat(config)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					t.Errorf("refusing to repair unexpected config fixture before cleanup: %v", err)
					return
				}
				if err := os.Chown(config, 0, 10001); err != nil {
					t.Errorf("restore config fixture ownership: %v", err)
				}
			})
		},
		"config-wrong-mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config"), 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"config-special-mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config"), os.ModeSticky|0o750); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, root string) {
			catalog := filepath.Join(root, "config", "catalog.json")
			if err := os.Remove(catalog); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("probe.env", catalog); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, root string) {
			ca := filepath.Join(root, "config", "dot-ca.pem")
			if err := os.Remove(ca); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(root, "config", "catalog.json"), ca); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, root string) {
			policy := filepath.Join(root, "config", "egress-policy.json")
			if err := os.Remove(policy); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(policy, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(policy, 0, 10001); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config", "catalog.json"), 0o660); err != nil {
				t.Fatal(err)
			}
		},
		"special-mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config", "catalog.json"), os.ModeSetuid|0o640); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-owner": func(t *testing.T, root string) {
			if err := os.Chown(filepath.Join(root, "config", "catalog.json"), 10001, 10001); err != nil {
				t.Fatal(err)
			}
		},
	}
	for _, spec := range candidateFileSpecs {
		for _, defect := range []string{"empty", "wrong-mode", "special-mode", "wrong-owner"} {
			name := spec.name + "/" + defect
			tests[name] = func(t *testing.T, root string) {
				path := filepath.Join(root, "config", spec.name)
				switch defect {
				case "empty":
					writeExact(t, path, nil, int(spec.uid), int(spec.gid), os.FileMode(spec.mode))
				case "wrong-mode":
					if err := os.Chmod(path, os.FileMode(spec.mode|0o020)); err != nil {
						t.Fatal(err)
					}
				case "special-mode":
					if err := os.Chmod(path, os.ModeSetuid|os.FileMode(spec.mode)); err != nil {
						t.Fatal(err)
					}
				case "wrong-owner":
					if err := os.Chown(path, 10001, int(spec.gid)); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	tests["oversized-ca"] = func(t *testing.T, root string) {
		raw := make([]byte, (1<<20)+1)
		writeExact(t, filepath.Join(root, "config", "dot-ca.pem"), raw, 0, 10001, 0o640)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root, _ := resetLinuxCandidate(t)
			mutate(t, root)
			if handle, err := OpenAdvisory(root); err == nil {
				handle.Close()
				t.Fatal("unsafe config object was accepted")
			}
			lease, err := restorelease.Acquire(root)
			if err != nil {
				t.Fatalf("failed construction leaked lifecycle lease: %v", err)
			}
			lease.Close()
		})
	}
}

func TestLinuxAdvisoryCollectorDetectsHeldFileUnlinkAndPoisons(t *testing.T) {
	root, _ := resetLinuxCandidate(t)
	handle, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if err := os.Remove(filepath.Join(root, "config", "catalog.json")); err != nil {
		t.Fatal(err)
	}
	if err := handle.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("Verify error=%v, want ErrPoisoned", err)
	}
}

func TestLinuxAdvisoryCollectorDescriptorsDoNotSurviveExec(t *testing.T) {
	if os.Getenv("RESTORECURRENT_EXEC_CHILD") == "1" {
		root := os.Getenv("RESTORECURRENT_PRODUCTION_ROOT")
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil && strings.Contains(target, root) {
				t.Fatalf("candidate descriptor survived exec: fd=%s target=%s", entry.Name(), target)
			}
		}
		return
	}
	root, _ := resetLinuxCandidate(t)
	handle, err := OpenIdentityBound(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	platform := handle.control.platform
	files := []*os.File{platform.root.file, platform.config.file}
	for _, held := range platform.files {
		files = append(files, held.file)
	}
	for _, file := range files {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFD, 0)
		if errno != 0 {
			t.Fatalf("fcntl(%s): %v", file.Name(), errno)
		}
		if flags&syscall.FD_CLOEXEC == 0 {
			t.Fatalf("descriptor %s is inheritable", file.Name())
		}
	}
	command := exec.Command(os.Args[0], "-test.run=^TestLinuxAdvisoryCollectorDescriptorsDoNotSurviveExec$", "-test.count=1")
	command.Env = append(os.Environ(), "RESTORECURRENT_EXEC_CHILD=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("exec child detected an inherited descriptor: %v\n%s", err, output)
	}
}

func TestLinuxAdvisoryCollectorSharedLifecycleAndConcurrentClose(t *testing.T) {
	root, _ := resetLinuxCandidate(t)
	first, err := OpenAdvisory(root)
	if err != nil {
		t.Fatal(err)
	}
	second := *first
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 24)
	for index := 0; index < 8; index++ {
		wait.Add(3)
		go func() { defer wait.Done(); errorsSeen <- first.Verify() }()
		go func() { defer wait.Done(); _, err := second.Observation(); errorsSeen <- err }()
		go func() { defer wait.Done(); errorsSeen <- second.Close() }()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil && !errors.Is(err, ErrClosed) {
			t.Fatalf("unexpected concurrent lifecycle error: %v", err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Observation(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed alias error=%v", err)
	}
}

func TestLinuxAdvisoryCollectorFailureDoesNotLeakLeaseOrSecrets(t *testing.T) {
	root, contents := resetLinuxCandidate(t)
	sentinel := "SECRET_CANARY_624df2"
	contents.env = append(contents.env, []byte("UNKNOWN="+sentinel+"\n")...)
	writeExact(t, filepath.Join(root, "config", "probe.env"), contents.env, 0, 0, 0o600)
	handle, err := OpenAdvisory(root)
	if handle != nil || err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("secret-safe construction failure violated: handle=%v err=%v", handle, err)
	}
	lease, err := restorelease.Acquire(root)
	if err != nil {
		t.Fatalf("failed construction leaked lifecycle lease: %v", err)
	}
	lease.Close()
}

func resetLinuxCandidate(t *testing.T) (string, configurationContents) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("restorecurrent root gate must run as uid 0")
	}
	root := os.Getenv("RESTORECURRENT_PRODUCTION_ROOT")
	if root == "" || os.Getenv("RESTORECURRENT_ROOT_TEST_ACK") != "ephemeral-ci-only-v1" {
		t.Fatal("restorecurrent root gate requires its explicit ephemeral CI acknowledgement")
	}
	if _, err := candidateInstance(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); err == nil {
		t.Fatal("restorecurrent root fixture already exists; refusing destructive reuse")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExact(t, filepath.Join(root, ".chengwang-m2b-candidate-root"), []byte(candidateMarker), 0, 0, 0o600)
	contents := validConfigurationContents(t, root)
	writeConfigTree(t, filepath.Join(root, "config"), contents)
	t.Cleanup(func() { cleanupOwnedTestRoot(t, root) })
	return root, contents
}

func writeConfigTree(t *testing.T, directory string, contents configurationContents) {
	t.Helper()
	mkdirExact(t, directory, 0, 10001, 0o750)
	writeExact(t, filepath.Join(directory, "probe.env"), contents.env, 0, 0, 0o600)
	writeExact(t, filepath.Join(directory, "catalog.json"), contents.catalog, 0, 10001, 0o640)
	writeExact(t, filepath.Join(directory, "dot-ca.pem"), contents.ca, 0, 10001, 0o640)
	writeExact(t, filepath.Join(directory, "egress-policy.json"), contents.policy, 0, 10001, 0o640)
	writeExact(t, filepath.Join(directory, candidateIdentityFileSpec.name), contents.identity, 0, 10001, 0o640)
}

func mkdirExact(t *testing.T, path string, uid, gid int, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeExact(t *testing.T, path string, raw []byte, uid, gid int, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func sortedMandatoryBlockers() []BlockerCode {
	value := append([]BlockerCode(nil), mandatoryBlockers...)
	sort.Slice(value, func(i, j int) bool { return value[i] < value[j] })
	return value
}

func fileFixture(name string, contents configurationContents) (fileSpec, []byte) {
	for _, spec := range candidateFileSpecs {
		if spec.name != name {
			continue
		}
		switch name {
		case "probe.env":
			return spec, contents.env
		case "catalog.json":
			return spec, contents.catalog
		case "dot-ca.pem":
			return spec, contents.ca
		case "egress-policy.json":
			return spec, contents.policy
		}
	}
	panic("unknown fixture file: " + name)
}

func cleanupOwnedTestRoot(t *testing.T, root string) {
	t.Helper()
	marker := filepath.Join(root, ".chengwang-m2b-candidate-root")
	raw, err := os.ReadFile(marker)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil || string(raw) != candidateMarker {
		t.Errorf("refusing to clean an unowned root fixture %s: %v", root, err)
		return
	}
	if err := os.RemoveAll(root); err != nil {
		t.Errorf("clean root fixture %s: %v", root, err)
	}
}
