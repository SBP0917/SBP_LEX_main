# TLA+ Tools 1.7.4 Candidate Dependency Provenance

Status date: 25 August 2026

Status: `CANDIDATE_DEPENDENCY_NOT_TRUST_ANCHOR`

The candidate dependency at
`runtime_artifacts/toolchains/tla2tools.jar` was compared byte-for-byte with the
official TLA+ v1.7.4 GitHub release asset:

`https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar`

Measured identity:

- bytes: `2274532`
- SHA-1: `bee4a54f3ee3d4afc347c3240ec2d9e93b075104`
- SHA-256: `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`
- SHA-512: `994c055a9128b4d792647dc699359d3f0f3b267735168a21ed4610932cb2044853835a602066b4c27d1b5a34c33813392926a7fbeca50d600c64a646a6ea4187`
- prospective Git blob OID: `fed0509682d1db8eb9abf20afc38ff779b08d8e0`
- manifest tag: `v1.7.4`
- manifest revision: `5a47802b5c391f59ecdd44117981f4ff8c0656ba`

The publisher's v1.7.4 release page publishes the same SHA-1. The local JAR has
no embedded `META-INF` signature file. These measurements establish exact
candidate bytes and source correspondence only. They do not establish an
independent signature, owner-approved trust pin, immutable P selection, formal
result admission, production custody, or external validation.
