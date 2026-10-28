# Routing data source attribution

No upstream file originals or bundled snapshot archive are distributed in the
current repository tree. The manifest records fixed commits, source URLs and
SHA-256 digests. Tools retrieve those files directly from the named projects and
verify the bytes before parsing. Raw bytes are stored only in the ignored local
`.cache/routing-audit/` directory, never committed or uploaded as CI artifacts.

- MetaCubeX/meta-rules-dat, revision
  `9f2b7462c7508ad85a1137e70d502b783c89794d`:
  https://github.com/MetaCubeX/meta-rules-dat/tree/9f2b7462c7508ad85a1137e70d502b783c89794d
  The project declares GPL-3.0. Consult its LICENSE and source notices.
- Aethersailor/Custom_OpenClash_Rules, revision
  `ce364895f9b55317159b43c0397788933f0f8448`:
  https://github.com/Aethersailor/Custom_OpenClash_Rules/tree/ce364895f9b55317159b43c0397788933f0f8448
  The author's original content is declared CC BY-SA 4.0; third-party material
  retains its own terms. Consult the upstream README and individual notices.

Derived samples, classification-policy labels and comparison reports remain for
audit reproducibility. Attribution is not a claim that every third-party right
has been independently resolved or that a domain is currently blocked/reachable.
This change does not relicense upstream material. Historical PR commits are not
rewritten; use squash merge to avoid importing the previously bundled originals
into the main branch's commit ancestry.
