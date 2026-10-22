# Official upstream verification fixtures

These are local compatibility test inputs. They do not authorize a release,
establish a production trust policy, or attest to a Chengwang image.

The original bytes below were fetched over HTTPS from immutable official GitHub
commit URLs and checked against the listed SHA-256 values. Keep their bytes
unchanged, including the absence of a final newline in `dsse.sigstore.json`.

| Local file | Upstream path | Bytes | SHA-256 |
|---|---|---:|---|
| message.sigstore.json | sigstore-conformance/test/assets/bundle-verify/happy-path-v0.3-new-mediaType/bundle.sigstore.json | 10054 | 82382358bdf586d1a184820ac0d0ff06eb737f459fe03baebbbd2c76e80b54a9 |
| dsse.sigstore.json | sigstore-conformance/test/assets/bundle-verify/happy-path-intoto-in-dsse-v3/bundle.sigstore.json | 11737 | 0b205ad5900e2f8009cb97a1e97c38e7759a64e4356ac97797bf3cbf7d7551c7 |
| artifact.txt | sigstore-conformance/test/assets/bundle-verify/a.txt | 109 | a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf |
| trusted-root.json | sigstore-go/pkg/testing/data/trusted-roots/public-good.json | 7014 | 4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c |

Pinned repositories:

- https://github.com/sigstore/sigstore-conformance/tree/43321d80f52958efa584c6c975716150db62180b
- https://github.com/sigstore/sigstore-go/tree/22d3691c7b8e0c5530fae3c05577690bfef5cd00 (v1.3.0)

Raw URL prefixes, followed by the upstream path without the repository name:

- https://raw.githubusercontent.com/sigstore/sigstore-conformance/43321d80f52958efa584c6c975716150db62180b/
- https://raw.githubusercontent.com/sigstore/sigstore-go/22d3691c7b8e0c5530fae3c05577690bfef5cd00/

Both bundles are official original v0.3 fixtures; no signed payload, certificate,
signature, SET, inclusion proof, checkpoint, or metadata was migrated or generated.
The default issuer and SAN are documented in upstream `test/assets/bundle-verify/README.md`:

```text
issuer = https://token.actions.githubusercontent.com
SAN = https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main
```

The DSSE statement uses `https://in-toto.io/Statement/v1`, one `a.txt` subject with
the artifact SHA-256 above, and `https://slsa.dev/provenance/v1`. Its predicate
builder refers to `loosebazooka/aa-test`; that claim is not the certificate signer
identity and is not a Chengwang build provenance claim. The beacon identity is
for tests only and must not be included in a production signing allowlist.

Both bundles contain Fulcio certificates, SCTs, Rekor v1 SETs, inclusion proofs
and signed checkpoints. They use verified Rekor integrated timestamps, not
RFC3161 timestamp authority responses.

License record: `LICENSE.sigstore-go` preserves the official sigstore-go Apache
2.0 license for its trusted-root fixture. At the pinned sigstore-conformance
commit, the repository root has no standalone LICENSE file (`LICENSE` returns
404). No license is invented or inferred for its samples here. These public
official samples are retained with their provenance for local compatibility
tests; product redistribution and third-party-license approval remain separate
unresolved release-review requirements.
