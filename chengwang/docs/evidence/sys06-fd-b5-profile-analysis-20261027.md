# fd / b5 CPU-profile narrow analysis

Status: `EVIDENCE_SUPPORTS_TWO_MEASUREMENT_TARGETS_NOT_A_CAUSAL_PERFORMANCE_FIX`.

## Evidence and window semantics

All four inputs are the already accepted public diagnostic artifacts. The producer, checker, profile-tag `TestMain`, `lifecycle.go`, and `lifecycle_v3.go` are byte-identical between fd and b5. Of the hot-path files inspected here, only `lifecycle_recovery_store.go` differs.

| Source | Mode | Profile wall window | Weighted CPU samples | Protobuf sample records | Function table | Capacity test | Package terminal |
|---|---|---:|---:|---:|---:|---:|---|
| fd `fdcdcea…` | single | 60.11s | 64.15s | 2676 | 600 | 85.57s | pass, 86.606s |
| b5 `b5b5fa9…` | single | 60.11s | 64.56s | 2718 | 609 | 78.10s | pass, 79.137s |
| fd | full | 120.15s | 117.62s | 4770 | 1356 | 67.73s | pass, 156.546s |
| b5 | full | 120.18s | 119.89s | 5012 | 1479 | 80.49s | timeout, 180.043s |

`sampleRecords` counts protobuf samples, not function calls. Weighted CPU seconds can exceed wall time because sampled work may run concurrently. Function-table size is not an invocation count.

The tagged `TestMain` starts CPU profiling immediately before `m.Run` and stops on a fixed 60-second or 120-second timer. Single mode starts the same capacity test at +0.027s (fd) and +0.024s (b5), so both profiles cover approximately the first 60 seconds of that test. Full mode is different: fd starts the capacity test at +74.118s and b5 at +90.331s. At profile stop, fd contains about 45.9 seconds and b5 about 29.7 seconds of that test; neither includes its completion. The b5 test that is still running at the final 180-second timeout starts at +179.900s, outside the profile window. Full profiles therefore cannot be compared as equal-stage samples or described as the full test duration.

The normal race command has no profile tag or profiler `TestMain`. Its b5 timeout occurs in a different test. The diagnostic profiles identify CPU families worth measuring, but do not by themselves explain the normal timeout.

## Self/leaf samples

Top self frames are dominated by race instrumentation in all four profiles:

| Profile | First self frames by weighted CPU |
|---|---|
| fd single | `__tsan::MemoryAccessRangeT` 12.44s; `racecall` 11.50s; `__tsan_read` 7.88s |
| b5 single | `__tsan::MemoryAccessRangeT` 15.21s; `racecall` 9.53s; `__tsan_read` 7.21s |
| fd full | `racecall` 26.02s; `__tsan_read` 19.45s; `__tsan::MemoryAccessRangeT` 15.57s |
| b5 full | `racecall` 23.22s; `__tsan_read` 19.17s; `__tsan::MemoryAccessRangeT` 15.52s |

Grouping only the displayed, unique flat rows gives lower bounds; dropped nodes are not assigned:

| Displayed self group | fd single | b5 single | fd full | b5 full |
|---|---:|---:|---:|---:|
| race/TSAN | 62.98% | 61.12% | 65.52% | 63.32% |
| `encoding/json` | 5.83% | 4.43% | 6.22% | 5.15% |
| SHA/hash-named frames | 1.26% | 1.44% | 1.65% | 1.43% |
| broad runtime allocation/GC/checkptr/memory | 12.91% | 13.99% | 8.44% | 10.38% |
| visible I/O/syscall | 0% | 0% | 0% | 0% |

The broad runtime row is not an allocation-only measure. For example, `runtime.mallocgc` cumulative weight ranges from 0.97s to 3.55s and `runtime.scanobject` from 0.96s to 2.03s, while checkptr and memory helpers account for other parts. The absence of displayed I/O self samples does not prove I/O is cheap: this is a CPU profile and the publication path performs disk verify/read/replace/readback at `lifecycle_recovery_store.go:460,466,483,501`, where blocked wall time need not appear as CPU self time.

## Cumulative frames

Cumulative rows are inclusive and nested. They must not be summed: `prepare…` includes `seal…`; `seal…` includes validation, JSON and hashing; `decode…` includes canonical re-encoding.

| Inclusive frame | fd single | b5 single | fd full | b5 full |
|---|---:|---:|---:|---:|
| `encoding/json.Marshal` | 9.42s | 11.03s | 13.93s | 16.18s |
| `prepareLifecycleCandidateAfterVerifiedBase` | 9.99s | 10.40s | 9.96s | 8.93s |
| `sealLifecycleV3Candidate` | 7.23s | 7.52s | 7.61s | 7.19s |
| `validateLifecycleV3ContentsScoped` | 3.77s | 4.02s | 7.73s | 8.42s |
| `decodeLifecycleRecord` | 1.48s | 1.37s | 11.82s | 15.24s |
| `lifecycleHash` | 3.30s | 3.40s | 5.15s | 5.37s |

`lifecycleHash` calls JSON marshal before SHA-256 (`lifecycle.go:134`), so its cumulative value is not SHA time. The visible `crypto/sha256.block` self samples are only 0.81–1.94s, whereas JSON marshal is materially larger. There is no evidence here that replacing the hash algorithm or weakening hashes is a useful or permissible fix.

The single profiles are the closest stage-aligned pair. Their main product frames are essentially the same order of magnitude despite the 7.47-second wall-time difference. The full profiles show reverse movement and unequal stage coverage. These data do not attribute fd→b5 timing changes to the trusted-base-copy source change.

## Two bounded measurement targets

1. **`sealLifecycleV3Candidate` at `lifecycle_v3.go:325`, reached from `prepareLifecycleCandidateAfterVerifiedBase` at `lifecycle_recovery_store.go:611`.** In the aligned single windows, the prepare frame is about 10 seconds cumulative and the seal frame about 7.2–7.5 seconds. A future opt-in measurement should split record-hash construction, `validateLifecycleV3ContentsScoped`, and the final canonical JSON marshal, and count calls/bytes. This is measurement only: the transition, trusted clock, owner/fence, complete-history validation and canonical-byte gates remain mandatory.

2. **`decodeLifecycleRecord` at `lifecycle.go:256`.** It is small in the aligned capacity profiles (1.37–1.48s) but large in the unequal full-suite windows (11.82–15.24s). If full-suite diagnosis continues, measure its duplicate-key token pass, typed `DisallowUnknownFields` decode, and canonical `encodeLifecycleRecord` pass separately. The present data do not support changing this function for the capacity test, and do not permit caching across operations or bypassing duplicate/unknown/canonical checks.

Do not change the 256-operation loop, 2 MiB record bound, 180-second gate, 688-name closure, full-history/every-plan validation, owner/fence/time/checkpoint checks, canonical hash, disk CAS/fsync/readback, or strict reopen decoder. Do not reintroduce cross-operation caches, mutable pointer proofs, JSON splice, or direct-publish shortcuts.

## Evidence boundary

This report does not identify a root cause or prove a performance improvement. It uses no new CI, Go execution, network request, private WAL, credential, or production data. It recommends only two narrower measurements supported by existing public profile and source evidence.
