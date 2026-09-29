# MIN Open Source / grant prepass

This is the public checklist for turning the living MVP into a reviewable grant
and Open Source demonstration. It is a checklist, not a claim that every item
is already complete.

## 1. Public repository contents

Keep these public:

- `README.md` — product scope, honest limitations, build/demo links;
- `SECURITY.md` — private reporting, safe harbor, security scope;
- `CONTRIBUTING.md` — reproducible checks and contribution rules;
- `LICENSE` — AGPL-3.0-only, subject to the owner's distribution/legal review;
- `docs/ROADMAP.md` — future work and release gates;
- synthetic tests, protocol specification and source code.

Do not publish `docs/`, production onion addresses, LAN addresses,
private keys, relay backups, logs containing operational metadata, or a
developer workstation's SSH/WireGuard/Tor configuration.

## 2. Release gates

- [ ] Clean checkout passes `cargo test --workspace`.
- [ ] `pod install` and the documented Xcode build pass from a clean checkout.
- [x] Release `MinCore.xcframework` is rebuilt without `dev-tcp-link`.
- [ ] One public demo path is documented: two clients, invite, send, receive,
      offline delivery and relay restart.
- [ ] Tor/onion path is tested from a network with censorship; bridge fallback
      is tested separately from the normal path.
- [ ] SBOM and dependency/license inventory are attached to the release notes.
- [ ] Secret scan covers the working tree and all Git history, not only HEAD.
- [ ] No claim of external audit is made until a dated report exists.

## 3. Security evidence

**Current status: an internal self-audit has been completed; no independent
external audit exists yet.** The self-audit found and fixed 11 defects (3 High:
prekey substitution, unauthenticated enqueue DoS, FFI use-after-free). The
verdicts per component are in
[`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md), and the working tracker is kept
internal. This must not be presented as an external audit.

Collect reproducible commands and results for:

- strict parser/fuzz corpus;
- E2E PQXDH/Double Ratchet and replay/ordering tests;
- relay memory-dump check (no client keys or plaintext);
- TTL/offline/restart behaviour;
- rate limits and queue caps;
- Tor bootstrap and failure modes;
- iOS Keychain/backup and fail-closed FFI behaviour;
- real iPhone validation from the mobile and Wi-Fi networks.

The public report should distinguish internal self-tests from an independent
review. A red-team agent can find implementation defects; it cannot replace an
independent external audit of the public release.
