# MIN — a private messenger

> **MIN** is a messenger where the content of a message is known only to the
> person it is addressed to. Not to us. Not to the relay. The goal is to reduce
> metadata as far as possible, without promising absolute anonymity: device
> compromise, user error and global traffic analysis remain outside the
> guarantees.

## The idea in three lines

1. **No accounts.** A user does not register: no phone number, e-mail, password
   or cloud profile. Identity is a cryptographic identity created locally on the
   device.
2. **No trust in the server.** The relay is an untrusted "dumb pipe": it holds
   opaque ciphertext, technical delivery state and a minimal auth state, but it
   has no private keys and cannot decrypt messages.
3. **Metadata is substantially reduced.** Transport goes over Tor by default.
   Background push notifications are not enabled in the MVP; delivery is pulled
   when the app is opened or activated. This does not mean absolute anonymity:
   global traffic analysis and device compromise remain outside the guarantees.

## Project status

MIN is a **working MVP**, not a set of mockups. On the current branch the full
1-to-1 E2E cycle over Tor/onion has been verified on two iOS simulators, plus
offline queueing, anti-replay, local encryption and delivery through a live
Raspberry Pi relay.

| Layer | State |
|---|---|
| Rust core | Working: identity, prekeys, PQXDH + Double Ratchet, storage/recovery, relay, FFI |
| iOS 15+ | Working MVP: contact by invite, send/receive text, error states, Tor bootstrap |
| Transport | C Tor + IPtProxy (obfs4/snowflake), SOCKS5 to onion; LAN fallback only for development |
| Relay | Raspberry Pi: loopback-only, Tor onion, RAM-only ciphertext, persistent auth state |
| Checks | Workspace tests, E2E over onion, RT-10 memory dump, RT-11 TTL, Xcode build |

**What is still missing before release:** a real iPhone instead of a simulator,
a secure short invite / username lookup, push wake-up, multi-device, an
independent external audit, and a legal decision on AGPL for the App Store. This
is listed in [Roadmap](docs/ROADMAP.md).

Development principle: **we do not change the UI, we add features.** The visual
language (black background, glass panels, grey cards) is fixed in
`MIN/Utilities/MINTheme.swift`.

## Design principles

1. **Security in layers, not a single algorithm.** Identity → device keys →
   session cryptography → local storage → relay isolation → Tor → metadata
   minimisation → anti-spam → protected update chain → independent audit.
   Compromising one layer is not account takeover.
2. **Local-first and autonomy.** Everything possible is decided on the device:
   identity, keys, contacts, history. The app is fully usable offline; the
   network is needed only for delivery. No background "phone home".
3. **Lightness and efficiency.** Minimal dependencies, audited libraries
   instead of home-grown ones, lazy loading, a tiny core binary, and careful
   treatment of battery (no permanent polling loops).
4. **Only proven cryptography.** No hand-rolled Double Ratchet. Protocols are
   built on auditable libraries; protocol parsers are fuzz-tested.
5. **Honesty towards the user.** We do not promise "absolute anonymity": device
   compromise, user error and global traffic analysis are outside our
   guarantees. Everything else is our work.

## Architecture

```
+-------------------------------------------+
|  iOS client (Swift + SwiftUI)             |
|   UI (Views/)  <->  local E2EE storage   |
|   dark "Liquid Glass"     (row-level AEAD)|
|            | FFI                          |
|     Rust core (min-ffi)                   |
|     identity, session, wire protocol     |
+---------------------+---------------------+
                      | Tor (C Tor + IPtProxy), default transport
              +-------v--------+
              | Relay         |
              | (UNTRUSTED)   |
              | opaque        |
              | ciphertext,   |
              | queue+auth    |
              +---------------+
```

- The **relay** is not a trust centre: it does not issue, restore or change
  identities, and cannot authorise a new device on its own.
- **Recovery is not a login.** A recovery code decrypts a local backup on the
  device and is **never** validated by the server.
- **Contacts are not a directory.** There is no global search for people. In the
  current MVP a contact is exchanged as a full invite string (Contact Key +
  prekey bundle); QR, short invites and `@username`-style lookup are post-MVP
  work.

## Threat model (whom we stand against)

| Adversary | Capability | What MIN must preserve |
|---|---|---|
| Passive network observer | Sees IP, time, volume and frequency of traffic | Content, and the fact of a conversation with a specific person |
| Untrusted relay | Full access to its own database, may drop or duplicate packets | No plaintext, no keys; replay protection |
| Relay compromise (database dump) | Dump of the whole server database | The dump is useless: ciphertext only |
| Surveillance / server coercion | Orders, data requests | Nothing to hand over: the server stores nothing decryptable |
| Local attacker | Physical access to the device | App lock, encrypted storage, policy-based wipe |

## Security invariants - true at all times

1. No plaintext ever reaches the relay.
2. No private key (identity/device/session) ever leaves the device.
3. The relay cannot authorise a new device on its own.
4. Recovery is a local, offline procedure; the server does not validate it.
5. An unknown Contact Request does not become a chat while discoverability is
   off. With it on (the default) a request is auto-accepted - a deliberate
   decision by the owner, and its cost is stated in
   [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md).
6. A revoked device cannot silently return to the trusted set.
7. A changed contact identity is detectable, and VERIFIED status resets.
8. A public contact record exposes no phone number or e-mail.
9. Protocol parsers reject unknown encodings instead of guessing.
10. Release logs contain no secrets and no plaintext.

## What is verified, and what is not

The audit was a self-hack run by the project, not an independent penetration
test. Verdicts per component are in
[docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md); the method and its normative
references follow a documented method: design review, implementation review,
adversarial testing, and a report with severity × difficulty per component.

**Checked by executable tests and proofs of concept:**

- the core's crypto path: PQXDH + Double Ratchet on libsignal, Contact Key bound
  to identity, identity-substitution detection, prekey rotation closing the
  previous address;
- transport: CBOR, padding and SOCKS parsers reject malformed input instead of
  guessing, and fail closed everywhere fail-open would be a hole;
- relay: claim-once, anti-replay, quotas, memory released on `ack`, no plaintext
  and no secrets in logs;
- the FFI boundary: handle ownership, C string lengths, no use-after-free;
- on-device privacy: contact identities are not stored in plaintext, long-term
  public keys do not reach syslog or iCloud backup;
- end-to-end delivery through a live onion service: 23/23 scripted checks
  against a real node.

**Stated honestly, NOT guaranteed at this stage:**

- independent third-party audit: **none**. All checks are self-run. The latest
  pass covered: `cargo test --workspace`, 332 tests, all passing; fuzzing, 82M
  iterations, **protocol parsers only** (`min-protocol`: envelope, frame
  request/response, wire framing, Contact Key) - the application layer `min-app`
  is **not** fuzzed, only unit- and E2E-tested; and a live E2E through a real
  onion service, **23/23 checks passed**, re-run 2026-09-28 on current code
  ([docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md));
- device-layer testing was a **manual** walkthrough, not an automated suite: the
  full flow (request from a stranger, auto-accept, invite, reply with a quote,
  read state and unread badges) was exercised on a physical iPhone and in the
  simulator, but there is **no scripted two-device iOS run**. The 23/23 E2E
  above drives the wire protocol against a real node, not the app UI over Tor;
- metadata leaks partially: the relay sees who talks to whom and how much, and
  lengths are bucketed into size classes, but that graph is not fully hidden;
- MVP limitations are listed in [docs/ROADMAP.md](docs/ROADMAP.md); part of that
  is known debt, not a gap in the work;
- discoverability is on by default: anyone holding your invite can write to
  you. This is a deliberate "convenience versus spam" trade-off.

## Privacy model: the current MVP and future elements

The current MVP implements full invite-text exchange, sending and receiving
text messages, local history and Tor/onion transport. Global search, short
invites, QR, `@username`, push and the extended privacy controls below are
separate future elements, not features of the current MVP.

**Contacts:** full invite text exchange; no global search and no `@username` in
the MVP. Fingerprint verification and QR UX are deferred to a separate design
review.

**Activity and extended settings (a future model, not the current MVP):**
online status, typing indicator, read receipts, disappearing messages, link
previews, per-chat overrides and additional privacy controls all require a
separate threat model and UI decision. The MVP does not claim them as working.

## Lightness and device autonomy

- **MVP:** network access only on an explicit action or activation; no
  background polling loops and no keep-alives. Launching the app or opening a
  chat may trigger a single pull, so the battery is not spent on a permanent
  network background.
- **Everything local is instant**: history, chat search and settings work
  without the network. The network is needed only for synchronisation.
- **Compact storage**: messages live in an encrypted local database with an
  auto-cleanup policy; media is on demand, with no automatic downloads.
- **Tiny binary**: the core is Rust with no runtime wrapper; the UI is native
  SwiftUI with no heavy cross-platform frameworks. App launch is a fraction of
  a second and UI-layer memory is minimal (lazy lists, no redraws).

## Roadmap

The current plan of record is in [docs/ROADMAP.md](docs/ROADMAP.md). A short
public summary:

- **Current MVP / grant preparation:** verify the actual defensive properties,
  reproduce E2E, collect security evidence, run a clean-checkout secret scan
  and prepare the application. A real iPhone is checked as part of the audit.
- **MVP+ after the grant:** speed up the first Tor start, automate backup
  transports, add further relay nodes and extend the regression harness.
- **Release 1:** a secure one-time invite and a considered search/username
  scheme without a permanent global identifier, content-free push, multi-device
  with recovery, independent audit.
- **After release:** Android, macOS, Windows and Linux clients on the same Rust
  core; groups, channels, bots, E2E media and calls.
- **Separate research, not a commitment:** our own blockchain and a built-in
  crypto wallet. A proprietary L1 is not needed for the MVP now and would bring
  a separate crypto audit, legal and financial risk; a working product and a
  clear monetisation model come first.
## Never do

- A users table with password/e-mail/phone; a user-search endpoint
- Storing private keys on the server
- Plaintext in APNs; plaintext or ciphertext in logs
- "TLS = encryption" (TLS is transport only, not E2EE)
- A hand-rolled Double Ratchet / our own crypto primitives
- Recovery used as a server-side credential
- Promises of full protection against global traffic analysis

## Definition of Done - v1 (acceptance criteria)

| Criterion | Pass condition |
|---|---|
| Identity | Two fresh installs create independent identities with no server registration |
| Contact | Full invite text yields a valid Contact Key; QR and short invite are post-MVP |
| Request | A stranger creates only a pending request |
| Spam | 1000 requests do not produce 1000 system notifications |
| Relay compromise | A database dump yields neither plaintext nor keys |
| Offline | The recipient picks up the queue on reconnect |
| Replay | A duplicate packet does not duplicate the message |
| Revoke | Not in the MVP: the certificate exists, but relay/AppCore do not integrate revoke yet |
| Recovery | A backup restores the identity locally, with no login |
| Tor | Production transport is Tor; the direct fallback is disabled by policy |
| Logs | Release logs contain no secrets and no plaintext |
| Fuzz | Wire parsers survive the fuzz corpus with no panics across the FFI |

## Licence and security

The project licence is **AGPL-3.0-only**, full text in [LICENSE](LICENSE).
Before any App Store release the owner must separately check the compatibility
of AGPL, Apple's terms and the subscription model: that is a legal decision, not
a technical guarantee.

Vulnerability reports and the safe-harbor policy are in
[SECURITY.md](SECURITY.md). Public plans and limitations are in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Supporting the project

Public donation addresses will be added by the owner after a separate check.
Until then, do not send funds to addresses found in third-party sources or in old
issues: they may be outdated or forged. Project wallets are deliberately not
listed at this stage - only addresses verified by the owner and recorded in this
section may be published. A safe support channel and the published addresses will
appear here once the owner confirms them.

## What will change in updates

The project is at MVP stage. Below is what is **known to change**, so a reader
does not mistake current behaviour for final:

| Today | Where it goes |
|---|---|
| Requests from strangers are auto-accepted (toggle default ON) | A separate requests screen and setting; the default may change to off |
| The `MINQ` first-message header (format in the protocol doc) | Replaced by a full request protocol; existing messages stay readable |
| Synchronous key exchange via invite code | Full QR/link exchange, without manual copying |
| Relay quotas and limits chosen by eye | Values will be calibrated against real load |
| Log format and FFI error format | Stabilised before the public release |

What will **not** change: the v1 wire format (`backend/PROTOCOL.md`) is frozen -
it is the contract between client and relay. Everything concerning the
cryptographic processes, the first-message format and the reply quote may change
between updates, and existing data stays readable.

Change history is in [CHANGELOG.md](CHANGELOG.md).

## Documentation

For a reader of the project:

- [SECURITY.md](SECURITY.md) - reporting, safe harbor, what is in scope.
- [CONTRIBUTING.md](CONTRIBUTING.md) - build, tests and contribution rules.
- [CHANGELOG.md](CHANGELOG.md) - what changed.
- [backend/PROTOCOL.md](backend/PROTOCOL.md) - wire format (v1, FROZEN).
- [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md) - what is verified and the verdicts.
- [docs/THREATS.md](docs/THREATS.md) - the threat model and its boundaries.
- [docs/ROADMAP.md](docs/ROADMAP.md) - what is deliberately not in the MVP.
- [docs/supply-chain/](docs/supply-chain/) - SBOM and dependency inventory.

Internal documents are deliberately not part of the public build
(`scripts/export-public.sh` excludes them): node deployment, access policy,
audit working trackers and agent notes. The owner decides which of those to show.

### About this repository

This repository is a **source snapshot**. It contains the code, the build
scripts and the documentation - it is **not** the development history. The
project is developed in a private repository; what is published here is its
tree, with the private material listed above removed, the relay address
replaced by a placeholder that each builder must set to their own node, and
the maintainer's Apple team id removed. Nothing here points at the
maintainer's infrastructure.

`DEVELOPMENT_TEAM` in `MIN.xcodeproj/project.pbxproj` is empty on purpose: a
team id identifies a developer account, and it is not build configuration
anyone else needs. Select your own team under Signing & Capabilities, or pass
`DEVELOPMENT_TEAM=<your-id>` on the `xcodebuild` command line.

An exported tree can be checked against its source with
`scripts/export-public.sh`, which refuses to produce output containing
untracked files, internal documents, a live `.onion` address or a signing
team id.

## Running your own relay

The client cannot send or receive anything without a relay to talk to. This
repository ships everything needed to run one: the relay listens on loopback
only and is reachable exclusively over its onion address.

The relay has **no registration and no accounts** — anyone who knows your onion
address can deliver ciphertext to you, and you can deliver to any mailbox id.
The onion address is a public rendezvous, not a secret, but the private key
behind it is: whoever holds it controls the address permanently.

**On a Raspberry Pi (or other ARM host), from your Mac:**

```bash
rustup target add armv7-unknown-linux-musleabihf
brew install messense/macos-cross-toolchains/armv7-unknown-linux-musleabihf

backend/deploy/build_relay.sh --deploy root@<pi-host>
```

**On an x86 VPS:** build natively on the server itself, where the toolchain
matches the target:

```bash
sudo apt install -y build-essential pkg-config
# then, on the server:
cargo build --release -p min-relay
```

**Prepare the node (on the host, as root):**

```bash
backend/deploy/bootstrap_node.sh
```

The script is idempotent and backs up every file it changes (`*.min-backup`).
It installs the Tor hidden service, the systemd unit, a ufw firewall and a
health timer. It does **not** open any port to the internet and does **not**
touch your router — the relay is reachable only through onion.

Useful flags: `--log-mode final` (less verbose logs), `--frame-port`,
`--onion-name NAME`, `--dry-run` (print what would happen, change nothing).

**Read your onion address:**

```bash
cat /var/lib/tor/min_relay/hostname
```

Back up the contents of `/var/lib/tor/min_relay/` somewhere safe and offline.
Losing it means losing the address permanently — it cannot be regenerated. It is
not in Git, by design.

**Verify the node end to end**, through the real onion service:

```bash
cd backend/deploy/tests
python3 e2e_onion_check.py --onion <your-onion> --socks 127.0.0.1:9050
```

Expected: `E2E RESULT: PASS — 23/23 checks`. You need a local Tor SOCKS proxy;
on the Pi one is configured as part of the admin setup.

## For developers

```bash
pod install                                  # Tor and IPtProxy modules
./backend/build-min-core.sh                  # build the Rust core into an xcframework
xcodebuild -workspace MIN.xcworkspace -scheme MIN \
  -destination 'platform=iOS Simulator,name=iPhone 17' build
```

Two hard requirements, and the usual causes of a broken build:

- build **only `MIN.xcworkspace`**, never `.xcodeproj` - the `Tor` and `IPtProxy`
  modules come from CocoaPods and are absent from the project;
- `MinCore.xcframework` is **not stored in git**: it is built by the script
  above, otherwise the linker will not find `-lmin_ffi`.

## Requirement sources

Full specification versions (Word, source documents, not in this repository):
- `MIN_TZ_v1_2_FINAL.docx` - technical specification v1.2 (architecture,
  protocol, relay, anti-spam, recovery, MVP scope, security invariants)
- `MIN_Privacy_Permissions_v1.0.docx` - privacy-controls catalogue v1.0
  (MUST/REC/EXT/LIMIT classification, per-chat overrides, High Privacy Mode)

This README is a structured summary; where they differ, the specification wins.
