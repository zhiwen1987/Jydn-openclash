# Trusted verified-base copy candidate v2: equivalence erratum

This file preserves and corrects the frozen v1 chain. It does not overwrite v1.

- v1 full patch SHA-256: `ef22a0d0e6ec3ca5908d7c35aec3115b19d35131225dd56c278e11e3b12c0564`
- v1 design erratum SHA-256: `92660ae9f948e0bbc6a57f05ac68b4db4be72e0dda034c15bf1b60c73c2193ff`
- immutable source base: `fdcdcea3f469670ed0edc08d180f991e150a3a66`

## v1 defect

v1 returned `errLifecycleUnsafe` when `json.Marshal` of the typed draft failed. That is not equivalent to the old raw-authoritative operation. A reachable same-package model can issue a valid base, then set both the store and base `LastTrustedAt` to the same UTC `time.Date(10000, ...)`. `base.valid` remains true and the closed clone succeeds, but `time.Time.MarshalJSON` rejects the out-of-range year. The old `json.Unmarshal` of the unchanged bound raw succeeds.

## v2 correction

Within `lifecycleVerifiedBase.copyRecord`, both canonical-Marshal error and canonical-byte mismatch now select the same existing `lifecycleTrustedJSONCopy(b.core.raw)` fallback. The pre-existing `b.valid` raw digest, exact raw bytes, typed equality, issuance, store ownership, poison/closed, and used-base gates still execute first. No caller bytes or changed typed image become the fallback input.

The existing top-level property test gains one subtest that proves all of the following rather than relying on setup failure:

1. The coordinated year-10000 typed image still satisfies the actual base validity gate.
2. `cloneTrustedLifecycleV3` succeeds.
3. Marshaling that clone actually returns an error.
4. `copyRecord` succeeds and its draft is deeply equal to the old JSON oracle.
5. Old and new record hashes and canonical bytes are equal, the bound raw is unchanged, and no disk write occurs.

Independent source analysis found no separate issued-valid-base value where the existing clone itself errors while the old bound-raw JSON copy succeeds: nil core is rejected by `b.valid`; type-schema closure already succeeded at issuance and is process-stable; all currently assigned representation errors already invoke raw JSON fallback inside the clone; other clone error values have no assignment; and the closed type graph excludes maps/interfaces/functions. Clone errors therefore remain fail closed in v2.

This remains source-only. Gofmt, compilation, Go tests, race/full acceptance, runtime behavior, and performance benefit are not established. The normal path is still clone plus Marshal rather than Unmarshal, so performance must be measured on Linux after independent review and root-only integration.
