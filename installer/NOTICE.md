# Source and redistribution notes

The bundle does not contain production subscription URLs, node credentials,
administrator passwords, SSH private keys or production databases. Site secrets
are generated or supplied at installation time and remain in restricted files.

Third-party components retain their own licenses, including the notices in the
Docker filesystem and Python wheels. These notices do not relicense this project.

- Mihomo: https://github.com/vernesong/mihomo , GPL-3.0. The binary declares
  `alpha-smart-gdaf3ad0`; the included corresponding declared source revision is
  `daf3ad03021cca6031f4a7303ca6d861a14d5a16`. This is version/source matching,
  not a claim of a reproducible binary build or embedded full VCS attestation.
- OpenClash prerequisites: https://github.com/vernesong/OpenClash . The plugin
  and router OS must be installed and checked independently.
- Uptime Kuma: https://github.com/louislam/uptime-kuma , MIT; CoreDNS:
  https://github.com/coredns/coredns , Apache-2.0. Bundled image digest and Kuma
  version are recorded in the package manifest.
- Python embedded distribution: https://www.python.org/downloads/windows/ ,
  PSF license included with the runtime. Windows 3.13.17 ZIP SHA-256 was compared
  with the digest in the official Sigstore bundle; signature verification is a
  separate property and is not claimed here.
- Paramiko and its dependencies are pinned by wheel name and SHA-256 against
  PyPI metadata in `sources/dependencies.lock.json`; each wheel includes its
  license metadata.
- Geodata source locations are recorded by `runtime/template.json` and the
  extracted payload manifest. These data files have their own terms and are
  snapshots, not a guarantee of current IP ownership or routing accuracy.

Geodata attribution accompanying the release:

- This product includes GeoLite2 data created by MaxMind, available from
  https://www.maxmind.com/ . GeoLite-derived data retains its applicable
  Attribution-ShareAlike terms; this notice does not replace those terms.
- Country snapshot source configured by the template:
  https://github.com/alecthw/mmdb_china_ip_list . Copyright (c) 2020 Alecthw;
  the project's MIT notice is included in `licenses/mmdb-china-MIT.txt`.
- GeoIP/GeoSite snapshot sources configured by the template:
  https://github.com/Loyalsoldier/v2ray-rules-dat . Its GPL-3.0 notice is in
  `licenses/v2ray-rules-dat-GPL-3.0.txt`; upstream data sources and their
  own attribution remain applicable.
- ASN snapshot source configured by the template:
  https://github.com/xishang0128/geoip . Its CC-BY-SA-4.0 notice is in
  `licenses/geoip-CC-BY-SA-4.0.txt`.
- Captured data bytes are unmodified by this release; hashes identify the
  exact snapshots. Configured URLs are provenance pointers, not a claim
  that a rolling upstream release still has identical bytes today.

The installer targets the specific verified platform set in its acceptance
report. It does not promise universal firmware compatibility, zero bugs, zero
DNS leakage or a measured multi-nine end-to-end availability rate.
