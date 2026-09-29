# Supply chain inventory (backend)

Generated: 2026-09-26T06:51:22Z

## Summary

| Source | Packages |
|---|---|
| crates.io | 609 |
| git (pinned to an exact revision) | 5 |
| workspace (our crates) | 17 |
| **total** | **631** |

## Git dependencies (provenance)

- `libsignal-core` 0.1.0 — git+https://github.com/signalapp/libsignal?tag=v0.102.2#8fc2113bda042fc972a166a24b974b0d34155c6c
- `libsignal-debug` 0.102.2 — git+https://github.com/signalapp/libsignal?tag=v0.102.2#8fc2113bda042fc972a166a24b974b0d34155c6c
- `libsignal-protocol` 0.1.0 — git+https://github.com/signalapp/libsignal?tag=v0.102.2#8fc2113bda042fc972a166a24b974b0d34155c6c
- `signal-crypto` 0.1.0 — git+https://github.com/signalapp/libsignal?tag=v0.102.2#8fc2113bda042fc972a166a24b974b0d34155c6c
- `spqr` 1.5.3 — git+https://github.com/signalapp/SparsePostQuantumRatchet.git?tag=v1.5.3#fd320484dcec89004021e6fdc7481825f5f261fa

All git dependencies (the whole Signal Protocol stack) are pinned in
`Cargo.lock` by **exact commit SHA**, not by tag name alone. That means the
build is reproducible: a retagged upstream release cannot silently change what
we build. Verified: 5 packages, 2 repositories, 2 unique SHAs.

## Our crates

| Crate | Licence |
|---|---|
| `min-app` | AGPL-3.0-only |
| `min-crypto` | AGPL-3.0-only |
| `min-delivery` | AGPL-3.0-only |
| `min-device` | AGPL-3.0-only |
| `min-e2e` | AGPL-3.0-only |
| `min-ffi` | AGPL-3.0-only |
| `min-identity` | AGPL-3.0-only |
| `min-net` | AGPL-3.0-only |
| `min-protocol` | AGPL-3.0-only |
| `min-recovery` | AGPL-3.0-only |
| `min-relay` | AGPL-3.0-only |
| `min-request` | AGPL-3.0-only |
| `min-session` | AGPL-3.0-only |
| `min-storage` | AGPL-3.0-only |
| `min-test-vectors` | AGPL-3.0-only |
| `min-tor` | AGPL-3.0-only |
| `min-wire` | AGPL-3.0-only |

## Licences of the crates.io packages

`Cargo.lock` does not store licences: that is normal, the `license` field is in
the crate metadata on crates.io. A full legal review of the licences
(compatibility with AGPL-3.0-only) is a separate task before publication and is
listed as a release gate in `docs/OPEN_SOURCE_PREPASS.md`.

## machine-readable

Full package list: `docs/supply-chain/sbom.json`.

