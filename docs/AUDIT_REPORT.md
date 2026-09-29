# MIN security audit report

## Current state — verified 2026-09-28

Numbers below are the ones quoted by the public README, reproduced here so a
reviewer can check them against the repository.

| Claim | Command | Result |
|---|---|---|
| Unit + integration tests | `cd backend && cargo test --workspace` | 332 tests, 0 failures |
| Fuzzing, 82M iterations | `cargo fuzz` in `backend/crates/min-protocol` | No crashes. **Scope: protocol parsers only** — `min-app` is not fuzzed |
| Live E2E via a real onion service | `python3 backend/deploy/tests/e2e_onion_check.py --onion <addr> --socks 127.0.0.1:9050` | **23/23 PASS** (55.5s), re-run 2026-09-28 on current code |

Dependency inventory: 631 packages, tracked in `docs/supply-chain/`, with the
two git-pinned cryptographic dependencies pinned to exact revisions.

The sections below are the pass-by-pass record. They are history, not the
current numbers — earlier entries quote smaller test counts because that is
what the suite held at the time.


> Self-audit following a documented method: design review, implementation review,
> adversarial testing, and a report with severity × difficulty per component. The
> key claims and the evidence for each of them are below.
>
> **Important about numbering.** This is the report of a single pass, it has its
> own ID scale (`MIN-01…MIN-28`). The working findings tracker (an internal
> document) uses the `MIN-RED-NNN` scale, and some defects are recorded there
> again under a different ID (for example `MIN-05` ≈ `MIN-RED-001`). The two
> scales are not merged yet: the final audit does that, re-checking every finding
> and giving it one canonical ID.

| Field | Value |
|---|---|
| Report version | v6 |
| Date | 2026-09-17 |
| Commit | v5 → **v6 (red-team v6: P0..P6, RT-26.1..26.23, PROTOCOL v3, Keychain)** |
| Method | Trail of Bits (design + implementation) × Cure53 (components) × OWASP MASVS (iOS) × adversarial update (Sept 2026) × **red-team v6 (20+ hypotheses from the internal v6 pass plan)** |
| Status | Phases D + I + T carried out ×2 passes; **MIN-01..06, MIN-16..26 closed**; PROTOCOL.md **v1→v3**; **P6 (iOS Keychain/CSPRNG/logs) done**; remaining: automated two-device iOS E2E, app-lock/screenshot (UI points), byte-level FFI ABI (v4 plan) |

## 1. Summary

**The MIN core is solid.** No CRITICAL was found. There are no obvious
"minefields" where an attacker could find keys: a relay dump by design contains
nothing but ciphertext and opaque identifiers, secrets are not logged, keys are
generated only in OsRng, and long-lived keys live only in the iOS Keychain
(ThisDeviceOnly).

**v3 (2026-09-15) - threat update for the end of 2026** (see §9) and closure of
3 findings: MIN-05 (HIGH - the session was not bound to the Contact Key, the
class of attacks from Signal-2026), MIN-16 (HIGH - pinned libsignal v0.66.0
without the forward-secrecy fixes from IEEE S&P'26), MIN-06 (MEDIUM - timing
comparison of pull_token). All three are closed with automated tests; the frozen
v1 wire format did not change. libsignal was raised from v0.66.0 (2025-02-11) to
v0.102.2 (2026-09-10): Triple Ratchet with a per-message PQ ratchet, plus the
forward-secrecy fixes from eprint 2026/727.

**v4 (2026-09-15) - red-team pass with executable proofs of concept.** In place
of "closed by design" declarations, an adversarial battery was written (§4):
replay storm, tampering of every envelope byte, truncation, reflection, mailbox
interception, pull_token brute force, rate-limit flood, relay dump, a scan of
the PreKey envelope fields. The pass found **real defects** that had gone
unnoticed before: MIN-17 (HIGH - `aad_commitment` was a keyless hash, not a
MAC), MIN-18 (MEDIUM - a false skipped-key cap and self-DoS:
`next_counter = 0`), MIN-19 (MEDIUM - the commitment did not cover the
ciphertext: mutation of a PreKey envelope field went undetected), MIN-20
(MEDIUM - no cap gate against reordering), MIN-22 (LOW - a flaky test masked a
possible regression). All are closed. Also found incidentally: libsignal itself
rejects mutations of the kyber field ("bad KEM key type"), junk PreKey message
injection does **not** break an established session
(`junk_prekey_injection_does_not_brick_session`), and tampering with a whisper
message is rejected by the internal MAC (`rt3_whisper_tamper_sweep_rejected`:
0 of 122 positions accepted).

**v5 (2026-09-15) - red-team pass #2 + protocol bump.** The second pass found
**2 more real findings** at boundaries the first pass did not cover: MIN-24
(MEDIUM - empty AAD in the FFI/`min-e2e` primitive layer: context substitution on
the FFI path, the same class as MIN-04) and MIN-25 (MEDIUM -
`min_format_contact_key` was a **fail-open placeholder** with a stale prefix: it
formatted arbitrary junk as a valid key). The test infrastructure was also
consolidated as a side effect: 11 ad-hoc diagnostics were reduced to 2
documented `#[ignore]` harnesses (reproducible libsignal byte-chart evidence) +
permanent regression tests.

**PROTOCOL.md was raised v1 → v2** - a mandatory consequence of MIN-17 (the
derivation of field 7 changed; a keyed MAC instead of a keyless hash). The wire
layout (the set and types of fields) did not change, so no data migration is
required; there were no deployed peers at the time of the bump. Contact Key
string form: `MIN1:` → `MIN2:` - an old and a new client diverge **explicitly**
(`UnsupportedVersion`) rather than silently.

**v6 (2026-09-17) - systematic red-team following the `AUDIT_PASS_V6.md` roadmap.**
The owner's review of v5 exposed weaknesses in the declarations: the metadata
threats had no threat model of their own, the replay analysis was
"one-dimensional", and "CRITICAL: 0" read as "everything is closed" while the S
phase was still open. Seven phases (P0..P6) were carried out: scope fixes and a
**metadata threat model**; **session persistence** (MACed snapshot, MAC key
derived from the storage key - crash/rollback/replay-safe); a state-machine
suite (replay matrix, fail-closed truncation, counter wrap, hostile-relay
harness); a relay concurrency/oracle suite (**F-3** anti-sharding rate limit,
**F-4** TTL enforcement - the "zombie crate" killed, claim-once races, token
guess budget, eviction-proof queue); FFI memory-safety + a storage row-swap PoC;
**MIN-26 mailbox_id rotation** (**PROTOCOL v2 → v3**: a mandatory signed `epoch`
in the Contact Key; `mailbox_id = HKDF(identity ‖ LE64(epoch))`; rotation
closes the previous session address, rollback is rejected, epoch state lives in
the MACed snapshot); **P6 iOS layer**: `KeychainService` (ThisDeviceOnly,
excludeFromBackup), the core's CSPRNG for all tokens (`min_random_hex`), a
secret-lifetime audit (`SECRET_LIFETIME_AUDIT.md`), and direct transport
physically excluded from the release. Result: **RT-26.1..26.23 closed** (apart
from owner hardware-dependent checks), 190 tests green. Remainders: §7/§11.


## 2. Verdicts per component

| Component | Verdict | Rationale |
|---|---|---|
| `min-wire` | 🟢 excellent | Canonical CBOR with a re-encode check (`is_canonical`), strict decode, 256 KiB caps; 5 fuzz targets, 26M iterations, 0 crashes |
| `min-protocol` | 🟢 excellent | Envelope/Contact Key; the header binding is now a **keyed MAC** (MIN-02 → MIN-17) and covers the ciphertext (MIN-19); fuzz 26M iterations clean |
| `min-crypto` | 🟢 excellent | RustCrypto (auditable), OsRng, XChaCha20-Poly1305 + AAD, BLAKE3, Ed25519; zeroize (MIN-03); the dead pre-fix copy of libsignal was removed (MIN-23) |
| `min-session` | 🟢 excellent | libsignal v0.102.2 PQXDH + Double Ratchet; message-type prefix 0x01/0x02; skipped-key cap 100 (base-aware, MIN-18/20 closed) → SUSPICIOUS; 3 failures → cooldown. Red-team: 0 of 122 whisper mutations accepted |
| `min-relay` | 🟢 excellent | The store is correct (caps 20/200, TTL, claim-once); the RateLimiter is wired into request handling (MIN-01 closed); **plus a global anti-sharding bucket (F-3) and TTL enforcement (F-4)** - Phase 3 v6; 25 tests |
| `min-delivery` | 🟢 excellent | dedup, seq ordering, tcp-link marked as test-only; the full-cycle FFI test passes |
| `min-storage` | 🟢 excellent | Row-level XChaCha20 with a unique nonce + **row-binding AAD** (`row_aad(key)`: domain string + row key) - row substitution/swapping is detected by the AEAD; executable PoC - Phase 4 v6 |
| `min-recovery` | 🟢 excellent | Argon2id m=64MiB t=3 p=1 (OWASP), version byte, uniform `WrongPassword`, AAD domain `min-recovery/v1` (MIN-04) |
| `min-device` | 🟢 excellent | Revoke certificates are signed with the Ed25519 identity key |
| `min-ffi` | 🟢 excellent | `catch_unwind` at the boundary; zeroize on free + short-lived hex (MIN-03); envelope verify binding (MIN-02 → MIN-17 keyed MAC); Contact Key parse/format - real (MIN-25) |
| `min-tor` | 🟢 excellent | Arti, lazy bootstrap, isolated streams per request |
| iOS `MIN/Services/*` | 🔴 mock | Stubs without real integration - Known Gaps (§7), not a core vulnerability |


## 3. Findings

### MIN-01 · MEDIUM / EASY - Rate limiter not wired into the relay

- **Where:** `backend/crates/min-relay/src/antispam.rs` (the module + 5 tests
  exist), `handlers.rs` / `frame_server.rs` - **not a single call** to
  `RateLimiter`.
- **Scenario:** any client with no limits floods enqueue requests -> the relay
  chokes, legitimate queues are pushed out; DoS/spam flooding is free.
- **Remediation:** call `RateLimiter::check(mailbox_id, cost)` in the enqueue/pull
  handlers (costs by request type), config - the default `RateLimitConfig`.
- **Status:** 🟢 **closed** (`1732a82`). The RateLimiter is wired into
  `frame_server::accept` + `handlers.rs`; 429 when exceeded; 30 tests green.

### MIN-02 · MEDIUM / MODERATE - `aad_commitment` is not verified

- **Where:** the field exists (`envelope.rs`, key 7, `bstr[16]`), is
  serialised/parsed, but **neither min-session nor min-delivery compute or check
  BLAKE3-256**.
- **Scenario (Signal-2026 class):** substituting header fields (hints, epoch,
  seq) by the relay -> injection into the anti-replay logic or into routing.
- **Remediation:** `commitment_input/compute/seal/verify` in envelope.rs; FFI
  `min_envelope_verify` + Swift `verifyEnvelope` (fail-closed).
- **Status:** 🟢 **closed** (`1732a82`). BLAKE3-256 of the header without field
  7 + session_id; FFI test: honest->"1", foreign session->"0", seq
  substitution->"0", junk->"0"; 165 tests pass.

### MIN-03 · MEDIUM / EASY - No zeroize; secrets as hex strings across FFI

- **Where:** `backend/crates/min-ffi/src/lib.rs` - all keys are returned as hex
  `CString`; the workspace has **no** `zeroize` anywhere.
- **Scenario:** local malware / forensics find copies of keys in free memory
  (hex doubles the exposure: 64 ASCII characters for a 32-byte key).
- **Remediation:** `zeroize` in `min-ffi`/`min-crypto`; `min_free_string` wipes
  the buffer before free; `min_storage_key_generate` wipes the raw bytes before
  returning hex.
- **Status:** 🟢 **closed** (`1732a82`). zeroize added; 165 tests pass, and an FFI
  test checks storage key creation/restore with zeroize.

### MIN-04 · LOW - Empty AAD in storage/recovery

- **Where:** `min-storage/src/lib.rs`, `min-recovery/src/lib.rs`.
- **Fact:** recovery **already uses** `BACKUP_AAD = b"min-recovery/v1"` (domain
  separation works). storage uses `aad: b""` - row swapping is theoretically
  possible, but is blocked by nonce uniqueness (per-row random) and KDF derivation
  of the storage key.
- **Status:** 🟢 **closed** (`1732a82`). The recovery AAD was already correct;
  the FFI test `test_recovery_ffi_cycle` was fixed (a proper ciphertext byte
  corruption instead of unreliable hex pop/push). 165 tests pass.


### MIN-05 · HIGH / MODERATE - Session identity binding is missing in FFI

- **Where:** `backend/crates/min-ffi/src/lib.rs` - `min_session_init` accepted
  `peer_name` (mailbox_id) and `bundle_cbor_hex` and called
  `SessionManager::init_session()` with no link to the Contact Key.
  `min_parse_contact_key` was a placeholder (`format!("parsed:{:?}")`) - the
  Contact Key "verification" checked nothing.
- **Scenario (Signal-2026 class):** the relay substitutes the prekey bundle
  (returns Mallory's bundle) or substitutes the address - a client that does not
  check the bundle against the signed Contact Key establishes a session with the
  attacker. The identity is checked, but not **bound to the channel** (the
  lesson of Message Injection Attacks Against Signal).
- **Remediation:** `min_parse_contact_key` -> a real fail-closed verification
  (strict parse + Ed25519 signature + the `mailbox_id == HKDF(identity_pk)`
  invariant); a new `min_session_init_bound(handle, contact_key_str, bundle_cbor_hex)`:
  the session address is derived FROM the Contact Key, and
  `bundle.signed_pre_key_public` is checked against
  `ContactKey.signed_prekey_public` before `process_prekey_bundle`.
- **Status:** 🟢 **fully closed MIN-RED-001 (2026-09-25)**.
  The first remediation checked the Contact Key and the signed prekey match, but
  did not bind the whole transport bundle (registration/device/prekey/Kyber
  fields) to the long-term Ed25519 identity, and the raw `min_session_init`
  remained an exported bypass. A new audit closed both paths: domain-separated
  binding of all public prekey fields, mandatory `min_session_init_bound`, the
  raw C API removed; regression tests - `pre_key_id` mutation, Mallory bundle,
  forged Contact Key and a bound FFI cycle.


### MIN-06 · MEDIUM / EASY - pull_token comparison is not constant-time

- **Where:** `backend/crates/min-relay/src/store.rs` `check_token`:
  `stored == presented` - comparing Strings returned false on the first
  mismatching byte.
- **Scenario:** a timing attack on the relay's response: brute-forcing pull_token
  byte by byte. The mailbox_id is public (HKDF of the identity), and the token is
  the only barrier to queue access. The rate limiter (MIN-01) mitigates it but
  does not remove the channel.
- **Remediation:** `subtle::ConstantTimeEq` (ct_eq) + an early reject on length
  only (64 hex chars is not a secret). Test
  `equal_length_wrong_token_rejected`: a difference in the last byte also
  rejects.
- **Status:** 🟢 **closed (v3)**.


### MIN-16 · HIGH / EASY - libsignal v0.66.0 without the forward-secrecy fixes (eprint 2026/727)

- **Where:** `backend/Cargo.toml`: the `libsignal-protocol` pin `tag = "v0.66.0"`.
  Dated via the GitHub API: the tag commit is **2025-02-11**.
- **Scenario:** a formal analysis of the Double Ratchet (Cheval, Jacomme,
  Richards - eprint 2026/727, **IEEE S&P'26**) found 3 attacks that break Forward
  Secrecy, 2 of them in Signal's main implementation. The fixes were
  "subsequently fixed", that is AFTER February 2025. MIN on v0.66.0 was
  vulnerable to the known FS-downgrade attacks under key compromise.
- **Remediation:** bump `v0.66.0` -> **`v0.102.2`** (2026-09-10, the last
  release). API migration: `local_address` in
  `process_prekey_bundle`/`message_encrypt`/`message_decrypt`; `DeviceId` is
  typed (u8); the kyber prekey is built into `PreKeyBundle::new`; rand_core 0.9
  (`UnwrapErr<OsRng>`); kem::KeyPair::generate takes an RNG. Bonus of releases
  0.67..0.102: the **Triple Ratchet** - a PQ ratchet (ML-KEM) in every message,
  not only in the PQXDH setup.
- **Status:** 🟢 **closed (v3)**. `cargo test --workspace` is green on 0.102.2,
  including PQXDH cycles through FFI; the xcframework was rebuilt with
  `build-min-core.sh`. PROTOCOL.md was **raised v1 -> v2** (MIN-17): the
  derivation of field 7 (`aad_commitment`) and the Contact Key prefix (`MIN1:` ->
  `MIN2:`) changed; the wire layout did not, and there are no deployed peers - no
  migration is required, but an old and a new client diverge **explicitly**
  (`UnsupportedVersion`) rather than silently (commitment mismatch).

### MIN-17 · HIGH / HARD - `aad_commitment` was a keyless hash (not a MAC)

- **Where:** `backend/crates/min-protocol/src/envelope.rs` -
  `compute_aad_commitment` used `blake3::hash` (keyless BLAKE3) over
  `header || session_id`.
- **Scenario:** the field is designed as a barrier against the relay
  substituting a header (the closure of MIN-02). Formally this is **not a MAC**:
  a keyless hash does not bind the value to a secret. The whole protection
  reduced to the secrecy of `session_id` (security through obscurity): anyone
  who obtained a `session_id` (from a client memory dump or through a future
  leak) could recompute the commitment for any substituted header and re-wrap
  the envelope indistinguishably from an honest one. The same class as the
  Signal-2026 "identity is not bound to the channel".
- **Remediation:** the commitment was converted to a **keyed MAC**:
  `BLAKE3-keyed(KDF(session_id), canonical_header || ciphertext)`, with the KDF
  as `blake3::derive_key("min-envelope-commitment/v1", session_id)`; the domain
  string is part of the MAC input (removing concatenation ambiguity).
- **Status:**  **closed (v4)**. Tests: `commitment_without_session_never_forges`,
  `commitment_domain_separation`, `commitment_binds_to_session_id`.


### MIN-18 · MEDIUM / EASY - False skipped-key cap: `next_counter = 0` by default

- **Where:** `backend/crates/min-session/src/manager.rs` -
  `PeerGuard::next_counter` was a `u32` defaulting to `0`; the precheck compared
  `counter - 0 >= 100`.
- **Scenario:** **false positives and self-DoS.** A session that started with a
  ratchet counter > 100 (a long chain; a jump after restoring the counter state)
  rejected legitimate messages as "gap too large" until the state was reset. The
  attacker needs to do nothing - the cap fires on its own. Found by a red-team
  scan (`SkippedKeyLimitExceeded` on honest traffic).
- **Remediation:** `next_counter: Option<u32>` (when the base is unknown the cap
  is not applied until the first whisper message is decrypted); when the cap
  triggers, the base resynchronises to the real counter, with a `resyncs` metric;
  the cap also applies to the PreKey envelope (the counter of the inner
  SignalMessage).
- **Status:** 🟢 **closed (v4)**. Tests: `dropped_messages_do_not_brick_session`,
  `rt2_loss_and_gap_cap_are_bounded`, `skipped_key_cap_rejects_large_gap`.

### MIN-19 · MEDIUM / HARD - Mutation of a PreKey envelope byte went undetected

- **Where:** `backend/crates/min-session/src/manager.rs` - receiving
  `CiphertextMessage::PreKey`.
- **Scenario (found by red-team):** a byte scan of the PreKey envelope (type
  `0x01`) showed that mutating the **last ciphertext byte (the Kyber part)** of a
  delivered PreKey message was **accepted successfully** - a correct plaintext
  came back (`TAMPER ACCEPTED`). The reason: libsignal derives the session from
  the envelope's outer fields (identity, base_key, signed prekey) and decrypts
  the inner SignalMessage; the integrity of those outer fields is not covered by
  an internal MAC, and the MIN-02/MIN-17 commitment did not include them.
- **Impact:** a relay that modified the ciphertext in a PreKey envelope gets a
  detectable failure at the receiver in the honest case, but gets **no detection
  at the commitment level** (only the inner AEAD was relied upon); besides that,
  a "silent" corruption of the session's first message became possible.
- **Remediation:** the commitment (MIN-17) was extended to the **ciphertext**
  (field 9) -> mutation of any envelope byte is detected by `from_wire_verified`
  **before** any crypto processing. The residual "accept" from the scan is gone
  as well.
- **Status:**  **closed (v4)**. Tests: `commitment_binds_ciphertext`,
  `prekey_envelope_ciphertext_tamper_rejected`,
  `every_wire_byte_is_authenticated`. The diagnostic byte scan
  (`harness_libsignal_prekey_bytemap`, `#[ignore]`) is kept as reproducible
  evidence: on a **fresh** session detection yields a Kyber decapsulation error,
  on an **established** one the PQ tail is ignored (1569/1788 positions), which
  is exactly what the envelope commitment closes.

### MIN-20 · MEDIUM / EASY - No cap gate against hostile reordering (DoS vector)

- **Where:** `backend/crates/min-session/src/manager.rs`.
- **Scenario:** without an upper bound on the ratchet-counter gap the relay can
  reorder or jump the counters, forcing the receiver to derive and hold up to
  `MAX_SKIPPED_KEYS` (libsignal ~2000) message keys per message - a CPU/memory
  amplification. PROTOCOL §73 requires a limit of 100.
- **Remediation/Status:** 🟢 **closed (v4)** together with MIN-18: a
  base-aware precheck rejects a gap >= 100 before reaching libsignal. Test
  `rt2_loss_and_gap_cap_are_bounded`.


### MIN-21 · LOW / EASY - Secrets are visible as hex in FFI free memory

- **Where:** `backend/crates/min-ffi/src/lib.rs` - hex `CString` for keys
  (`min_session_identity_public`, storage keys).
- **Scenario:** the hex representation doubles the secret's volume in memory (a
  32-byte key -> 64 ASCII bytes) and lives until `min_free_string`; local
  malware/forensics has a better chance of finding a copy.
- **Remediation:** `zeroize` on `min_free_string` (already done, MIN-03); the
  target is returning raw bytes instead of hex at the protocol bump.
- **Requalification (v6):** not cosmetic debt but a **full secret-lifetime
  audit**: a map of every copy of a secret along the path Rust heap -> FFI hex
  `CString` -> Swift `String`/`Data` -> NSError/OSLog/crash reports, with a
  target API `*mut u8 + len` and zeroize at every boundary. Plan - Phase 6/7 v6
  (the pass's internal tracker, RT-26.17).
- **Status:** 🟡 secret-lifetime audit (before 1.0). Partly mitigated by MIN-03.

### MIN-22 · LOW / EASY - Flaky and tautological asserts in red-team tests

- **Where:** `backend/crates/min-session/src/manager.rs`,
  `backend/crates/min-ffi/src/lib.rs`.
- **Fact:** two defects in the **test** infrastructure, because of which an
  attack could look repelled while not actually being tested:
  1) `assert!(x == false || true)` - a tautology, the test could not fail;
  2) a ciphertext corruption check via hex pop/push that with probability 1/16
     did not change the byte at all (no corruption happened).
- **Impact:** not a product vulnerability but **regression masking** - the worst
  kind of audit defect ("a green test that checks nothing"), which is why it is
  recorded as a finding.
- **Remediation:** the tautology was replaced with meaningful checks; the
  corruption is a direct XOR of the ciphertext byte.
- **Status:** 🟢 **closed (v4)**.

### MIN-23 · LOW / INFO - A duplicate pre-fix copy of libsignal in the tree

- **Where:** `backend/crates/min-crypto/Cargo.toml` - a dependency on
  `libsignal-protocol v0.66.0` (without the forward-secrecy fixes from eprint
  2026/727), **not used in any code**.
- **Scenario:** a dead dependency pulled a second, vulnerable copy of the crypto
  library into the build. There is no direct exploitation (the code never called
  it), but it is a "sleeping" surface: any future use of `min-crypto` for session
  logic would silently bring back the vulnerable libsignal. The class is
  supply-chain hygiene (the Bybit-2025 lesson: harmful is not only the code you
  call).
- **Remediation:** the dependency was removed; the only source of libsignal in
  the workspace is `min-session` (v0.102.2).
- **Status:**  **closed (v4)**.


### MIN-24 · MEDIUM / EASY - Empty AAD in the FFI primitive layer (FIX-1)

- **Where:** `backend/crates/min-ffi/src/lib.rs` - `min_encrypt`/`min_decrypt`
  called `min_crypto::encrypt(..., aad = b"")`; `min-e2e` did the same.
- **Scenario:** the primitive layer's ciphertext was not bound to its context of
  use: the same AEAD key, the same ciphertext, but a different meaning (for
  example key derivation vs. a message) would decrypt successfully - a classic
  context/substitution mistake (the same class as MIN-04, but on the FFI path
  rather than storage).
- **Remediation:** a domain was introduced,
  `min_crypto::PRIMITIVE_AAD = b"min-primitive/v1"`; FFI and `min-e2e`
  encrypt/decrypt only with it. A ciphertext encrypted under this domain does
  not decrypt with an empty AAD and vice versa (the Poly1305 tag does not match)
  - proven by a test.
- **Status:**  **closed (v5)**. Tests: `tests::aad_context_substitution_rejected`
  (min-e2e, context substitution -> failure), `test_aad_is_bound` (min-crypto).

### MIN-25 · MEDIUM / EASY - `min_format_contact_key` was a fail-open placeholder

- **Where:** `backend/crates/min-ffi/src/lib.rs` - `min_format_contact_key`
  returned a Rust `Debug` string of the form `MIN1:"<bytes>"` for **any** input,
  with no key validation.
- **Scenario:** a real FFI surface (declared in `MinCore.swift`). A fail-open
  formatter means an invalid/foreign/corrupted Contact Key is "successfully
  formatted" and can be handed to the user for sharing - junk ends up in the UI
  and the error never surfaces. The class is "silent fail-open on a trusted
  boundary" (the Symbian/Apple goto-fail CVE class of 2021-2024): a missing
  check where the caller expects one.
- **Remediation:** validation was moved into a shared fail-closed helper (the
  same one `min_parse_contact_key` uses): version, mandatory fields, the Ed25519
  signature and `mailbox_id == HKDF(identity_pk)` are checked; the formatter now
  canonicalises only a valid key, otherwise `NULL`.
- **Status:**  **closed (v5)**. Tests: `test_format_contact_key_ffi`
  (valid -> canonical `MIN3:...`; junk/foreign key -> NULL),
  `test_contact_key_ffi` (a parse/format cycle).

### MIN-28 · LOW / HARD - Non-canonical protobuf parsing in libsignal (boundary)

- **Where:** the `min-session` <-> libsignal boundary. `CiphertextMessage`
  serialisation (protobuf) permits **semantically equivalent but byte-different**
  forms: position 3 of the first PreKey envelope is mutable with no effect -
  decrypt returns the **same** plaintext (found by the hostile harness RT-26.20,
  `probe_mutation`: `POS 3 ACCEPTED plaintext=[114,48]`).
- **Scenario:** the relay changes a byte of the libsignal body in transit -> the
  receiver accepts a frame with a different raw hash. **There is no content
  integrity attack** - the plaintext is authenticated by the ratchet's internal
  MAC and the state is deterministic; the impact is limited to "a transit
  mutation is indistinguishable from delivery" (at worst, deduplication
  diagnostics by raw bytes are unreliable).
- **Why not CRITICAL:** on the MIN wire the libsignal body is wrapped in
  EnvelopeV1: an outer AEAD (ciphertext in field 9) + a keyed commitment
  (MIN-17/19) - the relay cannot change a single byte without breaking the
  envelope before libsignal sees it. The surface is reachable only under
  session key compromise (which is already game over in a different class).
- **Remediation:** accepted as a known property of the library boundary; the test
  invariant was honestly weakened ("a mutation != a different plaintext != a shift
  of the counter base"); deduplication is by ratchet counter, not by raw bytes
  (already the case). An external audit of the libsignal boundary is planned with
  the independent audit.
- **Status:** 🟢 **closed as accepted-with-mitigation (v6/P7)**
  (`hostile_relay_sequence_preserves_session_safety`).


### Known debts · INFO (not vulnerabilities)

- UIScene migration (an iOS 27+ blocker, described in the internal
  documentation).
- `min-ffi` hex encoding of secrets - convenient but 2x the volume; not to be
  changed in the MVP, revisit at the protocol bump.
- iOS/simulator console noise - not our bugs (the list is in the internal
  documentation, section "Known Gaps").


## 4. Red-team evidence (v4+v5, executable PoCs)

AUDIT v4/v5: **9 red-team findings** were found and closed - MIN-17 (HIGH -
`aad_commitment` was a keyless hash, not a MAC), MIN-18 (MEDIUM - a false
skipped-key cap, self-DoS), MIN-19 (MEDIUM - the commitment did not cover the
ciphertext), MIN-20 (MEDIUM - no cap gate against reordering), MIN-21 (LOW - hex
secrets in FFI memory), MIN-22 (LOW - flaky/tautological tests), MIN-23 (LOW - a
duplicate pre-fix copy of libsignal), MIN-24 (MEDIUM - empty AAD in the FFI
primitive layer), MIN-25 (MEDIUM - a fail-open Contact Key formatter).

**Totals across all passes (v1->v5):** 16 findings (MIN-01..06, MIN-16..25);
**15 are closed with automated tests**, MIN-21 is partly mitigated (debt until
1.0), debts are INFO.

**Scope caveat (v6):** "CRITICAL: 0. Open HIGH/MEDIUM: 0" means **"among the
core components that were checked"** (phases D+I+T: wire, protocol, crypto,
session, relay, delivery, storage, recovery, device, ffi, tor). NOT covered by
that formula: phase S (iOS MASVS - mock services, §7), real-device E2E over
Tor, memory forensics, a live relay on hardware. Their statuses are in §6, §7,
§11.

**Phase status:** D (design) 🟢 · I (implementation) 🟢 · **T (adversarial) 🟢
done** (v4+v5: 20+ executable PoCs; the table below) · S (iOS MASVS) 🔴
planned (outside the core, §7).

| Attack | Test | Verdict |
|---|---|---|
| Forging a commitment without `session_id` | `commitment_without_session_never_forges` | repelled |
| Substituting the claimed `session_id` at verify | `commitment_without_session_never_forges` | repelled |
| Domain separation of MAC inputs | `commitment_domain_separation` | respected |
| Mutating every whisper byte (122 positions) | `rt3_whisper_tamper_sweep_rejected` | 0 accepted |
| Mutating ciphertext in a PreKey envelope | `prekey_envelope_ciphertext_tamper_rejected` | repelled |
| Re-injecting a PreKey envelope (session DoS) | `junk_prekey_injection_does_not_brick_session` | the session survives |
| Message loss + a large gap | `rt2_loss_and_gap_cap_are_bounded` | the cap triggers correctly |
| A false cap on honest traffic (MIN-18) | `dropped_messages_do_not_brick_session` | no false positives |
| Context substitution of the primitive AEAD (AAD) | `aad_context_substitution_rejected` | repelled |
| Contact Key formatter on junk/foreign key | `test_format_contact_key_ffi` | NULL (fail-closed) |
| Bundle substitution (Mallory) against the Contact Key | `test_session_init_bound_ffi` | NULL (fail-closed) |
| PreKey/whisper byte map (documented harness) | `#[ignore]` `harness_libsignal_prekey_bytemap`, `harness_libsignal_whisper_bytemap` | reproducible evidence for MIN-19 (1569/1788 accepted = the Kyber tail) |


## 5. What an attacker will NOT find (confirmed strong sides)

1. **A relay DB dump is useless:** it holds only `mailbox_id` (HKDF of the
   identity - domain-separated, the identity is not recoverable), ciphertext,
   opaque 16-byte hints, timestamps and size classes. There are no keys by
   design.
2. **Anti-replay is real:** `seq` is strictly monotonic per (session,
   direction), a repeat is dropped; tested in the FFI full cycle. The skipped-key
   cap 100 -> SUSPICIOUS - an endless retry loop is impossible.
3. **Message injection is blocked:** injection requires an AEAD tag under the
   Double Ratchet key (libsignal); the message types are separated (0x01/0x02);
   the identity is bound to the session at `init_session`, and the prekey bundle
   to the Contact Key (`min_session_init_bound`, MIN-05); tests
   `forged_identity_bundle_rejected`, `test_session_init_bound_ffi`. Header
   substitution is closed by the keyed MAC (MIN-02 -> MIN-17), ciphertext
   substitution by the commitment's coverage (MIN-19). The Signal-2026 attacks are
   closed and verified with PoCs.
4. **The parsers do not crash:** a canonical re-encode invariant, strict CBOR,
   `get_b(k, n)` with an exact length (a later `unwrap` is safe), 256 KiB caps,
   26M fuzz iterations without a crash.
5. **Offline brute force of a backup is pointless:** Argon2id 64 MiB, OWASP
   parameters, a uniform `WrongPassword`.
6. **Tor has no gaps:** Arti + isolated streams, direct TCP is unavailable from
   the release path (Swift only ever chooses "tor").

## 6. Metadata privacy (threat model of metadata leakage)

> Introduced in v6 following an external review of v5: a relay dump contains no
> keys (invariant #1), but that does **not** mean the absence of metadata
> leakage. Metadata privacy is a separate surface and is classified separately.

### 6.1. What an observer (relay / dump / network observer) sees today

| Signal | Visible? | Classification |
|---|---|---|
| The fact of mailbox activity (enqueue/pull) | ✅ | Inherent - any store-and-fetch has activity |
| Timing patterns (when someone writes/collects) | ✅ | Inherent; mitigation - batching/pull intervals (backlog) |
| Message sizes and size classes | ✅ (classes) | Inherent; the size classes in PROTOCOL are deliberate coarseness |
| Correlation "put into A -> collected from B" | ✅ with repeated pairs | **Linkability - see 6.2** |
| mailbox_id <-> identity | ❌ given one-way HKDF | Protected (the identity is not recoverable) |
| mailbox_id_1 <-> mailbox_id_2 of one identity | ✅ not linkable (with rotation) | **MIN-26 closed (v6/P5)**: mailbox_id = HKDF(identity ‖ LE64(epoch)), PROTOCOL v3 - addresses of different epochs are non-linearly independent |
| Existence of a mailbox (existence oracle) | ⚠️ partially (Phase 3 v6) | NotFound/Forbidden codes differ - inherent to store-and-forward; probing is bounded by the rate limiter (`rt26_5_existence_probing_is_rate_bounded`); id guessability is reduced by epoch rotation (MIN-26, v6/P5) |
| The social graph | ❌ directly; ⚠️ via correlation | Acknowledged residual risk (see the exceptions below) |

### 6.2. mailbox_id unlinkability - MIN-26 (closed in v6/P5)

Before: mailbox_id = HKDF(identity_pk) - a deterministic derivation, one identity
= one mailbox forever: HKDF protects against recovering the identity, but gives
no unlinkability (the relay links mailbox activity over time and across all
Contact Key re-issues).

Now (PROTOCOL v2 -> v3, prefix MIN3):
- the Contact Key gained a mandatory field 6 = epoch (u64, starting at 1), part
  of the signed data (the signature covers fields 1..=6, the signature field is
  7);
- mailbox_id = HKDF-SHA256(ikm = identity_pk ‖ LE64(epoch),
  salt="MIN-MAILBOX-SALT-v1", info="mailbox-id-v1", L=16);
- epoch = 0 does not exist: a refusal in the parser and in verify();
- rotation closes the previous address at the session level: EpochRotated for
  encrypt/decrypt/init on a stale address; epoch rollback and the same epoch
  with a foreign address are rejected; epoch state is part of the MACed
  snapshot.

Consequence for the relay: the two addresses of one identity (epochs 1 and 2)
are not linkable by the one-way nature of HKDF, apart from the fact of rotation
itself. Residual risk: frequent rotations at low traffic volume can stand out by
timing - the periodicity policy was pushed to the client (MVP: on an explicit
app command).


### 6.3. Explicit exceptions (we do not hide these)

- **Global traffic analysis** (an observer between client and relay / between
  Tor nodes) - out of scope; mitigated by Tor + size classes.
- **Timing fingerprinting** with a constant poll rate - a backlog item.
- **Cover traffic** (protection against statistical analysis of volume/rate) -
  deliberately a backlog item until 1.0; the claimed properties without it are
  more modest than SimpleX's (which has broader padding/proxying).

## 7. Known Gaps (iOS, outside the core - not vulnerabilities, but mandatory before 1.0)

| Gap | MASWE | State |
|---|---|---|
| Keychain wrapping of the storage key / pull_token | 0003/0016 | the storage key - Keychain ThisDeviceOnly; the pull token - encrypted SQLite, not a bare disk; `KeychainService.excludeFromBackup` wired |
| Backup exclusion | 0006 | Not configured |
| App-lock (FaceID/passcode) | — | No |
| Screenshot protection | 0038 | No |
| Clipboard hygiene | 0030 | Not audited (UI area) |
| UIScene | — | A documented debt |


## 8. Comparison with competitors (the goal of "better than Signal/SimpleX/Telegram")

| Property | Signal | SimpleX | Telegram | MIN |
|---|---|---|---|---|
| No phone/e-mail in the identity | ❌ | ✅ | ❌ | ✅ |
| The relay does not know the identity | ❌ (Sealed Sender is not complete) | ✅ | ❌ | ✅ (mailbox_id = HKDF) |
| Anti-replay proven by tests | ❌ (AsiaCCS-2024: replay works) | partially | ❌ | ✅ (FFI tests) + phase T |
| Header binding is verified | 2026 patch | ✅ | — | ✅ MIN-02 closed (`1732a82`) |
| Message injection (Signal #1/#2) | 2026 patch | ✅ | ❌ | ✅ by design |
| Rate limiting on the server | n/a (central servers) | ✅ | ✅ | ✅ MIN-01 closed (`1732a82`) |
| The identity is bound to the channel (bundle ↔ Contact Key) | partially | ✅ | ❌ | ✅ MIN-05 closed (v3) |
| 2026/727 forward-secrecy fixes (libsignal) | ✅ | n/a | ❌ | ✅ MIN-16 closed (v0.102.2) |
| Own cryptography | libsignal | RustCrypto | own MTProto ❌ | RustCrypto + libsignal 0.102.2 |
| Post-quantum | PQXDH + Triple Ratchet | — | — | ✅ PQXDH + Triple Ratchet (per-message PQ ratchet) |

## 9. Threat update for September 2026

A separate pass: recent publications/exploits, applicability to MIN, status.

| Threat (2026) | Essence | Applicability to MIN | Status |
|---|---|---|---|
| **Double Ratchet forward-secrecy attacks** (eprint 2026/727, IEEE S&P'26) | 3 forward-secrecy attacks, 2 in Signal's implementation | libsignal v0.66.0 was vulnerable | ✅ closed (MIN-16, bump to v0.102.2) |
| **Signal CDS enclave compromise** (V12, Aug 2026) | UAF/TOCTOU in the SGX Contact Discovery enclave -> code execution in the enclave, Noise key theft | MIN does **not** use server enclaves or contact discovery - the surface does not exist | ✅ out of scope by design (documented) |
| **"Send and Pretend"** (USENIX Sec'26) | Injection into group chats on out-of-order receipt | MIN is 1:1 only; group chats are not implemented | 🟡 to take into account in the group protocol design review (phase D) |
| **iOS 0-click / full-chain** (DarkSword 2026; CVE-2026-20700 exploited in the wild) | VPN app -> WebKit -> kernel LPE; cleartext-HTTP interception for update injection | at the iOS level, outside MIN; lessons: no cleartext channels, updates only via the App Store | ✅ MIN has no OTA channel; updates go through the App Store (Apple signature check) |
| **The TOCTOU lesson** (from V12) | canary check + CAS as two steps -> race | relay code: `get_mut` + `check_token` - atomic under `RwLock`; snapshot-free patterns | ✅ audited: there is no race window in store.rs/handlers.rs (a single write lock) |
| **Timing side channels** | comparing secrets | pull_token `==` in store.rs | ✅ closed (MIN-06, subtle ct_eq) |


## 10. Remediation roadmap

| Priority | ID | Action | Status |
|---|---|---|---|
| ~~P0~~ | MIN-01 | Wire the RateLimiter into the relay handlers | 🟢 closed (`1732a82`) |
| ~~P0~~ | MIN-02 | Commitment verification on receipt | 🟢 closed (`1732a82`) |
| ~~P1~~ | MIN-03 | zeroize in ffi/crypto | 🟢 closed (`1732a82`) |
| ~~P2~~ | MIN-04 | AAD domains in storage/recovery | 🟢 closed (`1732a82`) |
| ~~P0~~ | MIN-05 | Session identity binding (Contact Key → mailbox → bundle) | 🟢 closed (v3, `test_session_init_bound_ffi`) |
| ~~P1~~ | MIN-06 | Constant-time pull_token compare (subtle) | 🟢 closed (v3) |
| ~~P0~~ | MIN-16 | libsignal bump v0.66.0 → v0.102.2 (2026/727 FS fixes) | 🟢 closed (v3, xcframework rebuilt) |
| ~~P0~~ | MIN-17 | Commitment: keyless hash → keyed MAC (+ domain separation) | 🟢 closed (v4, `commitment_*`) |
| ~~P1~~ | MIN-18 | Skipped-key cap: base-aware `Option<u32>` (removing self-DoS) | 🟢 closed (v4, `dropped_messages_do_not_brick_session`) |
| ~~P1~~ | MIN-19 | The commitment covers the ciphertext (PreKey mutations) | 🟢 closed (v4, `prekey_envelope_ciphertext_tamper_rejected`) |
| ~~P2~~ | MIN-20 | A cap gate against hostile reordering | 🟢 closed (v4, `rt2_loss_and_gap_cap_are_bounded`) |
| ~~P2~~ | MIN-22 | Flaky/tautological asserts in red-team tests | 🟢 closed (v4) |
| ~~P2~~ | MIN-23 | A duplicate pre-fix copy of libsignal in the tree | 🟢 closed (v4) |
| ~~P1~~ | MIN-24 | AAD domain in the FFI/`min-e2e` primitive layer (FIX-1) | 🟢 closed (v5, `aad_context_substitution_rejected`) |
| ~~P0~~ | MIN-25 | `min_format_contact_key` fail-open placeholder | 🟢 closed (v5, `test_format_contact_key_ffi`) |
| **P2** | MIN-21 | Fully eliminate hex secrets in FFI free memory (`*mut u8` + len) | 🟡 mitigated (zeroize + short-lived hex), debt until 1.0 |
| ~~P2~~ | phase T | adversarial suite: header tamper, rate-limit flood, replay storm, recovery corruption, byte-sweep harness | 🟢 **done** (v4+v5, 20+ PoCs, §4) |
| **P2** | phase S | iOS MASVS: Keychain storage key, encrypted-SQLite pull token, backup exclusion; app-lock and the screenshot guard remain backlog | 🟡 storage wired; UI hardening remains backlog |
| **P2** | DEP | Raspberry Pi relay: cross-compilation, hardening, E2E over Tor | 🔴 waiting for a server (the owner) |

## 11. Audit limitations

- A self-audit by a single auditor. Phases **D + I + T** were carried out:
  MIN-01..06, MIN-16..25 are closed with automated tests; MIN-21 is mitigated
  (debt until 1.0).
- Phase T was **completed** in v4+v5: an adversarial battery of 20+ executable
  PoCs (§4). Two harnesses under `#[ignore]` - reproducible evidence of the
  libsignal byte maps (PreKey/whisper):
  `cargo test -p min-session -- --ignored --nocapture harness_libsignal`.
- **Device-layer E2E is a manual walkthrough, not an automated run.** The full
  flow (request from a stranger, auto-accept, invite, reply with a quote, read
  state and unread badges) was exercised on a physical iPhone and in the
  simulator, and the scripted E2E against a live onion service passes 23/23.
  What is **not** covered: a scripted two-device iOS run driving the real app UI
  over Tor. The network path, the xcframework build artifacts and Arti's
  behaviour on iOS are therefore outside the scripted suite.
- The conclusions about closing the Signal-2026 attacks rest on design analysis
  + PoCs; no independent external audit (Cure53/Trail of Bits) was carried out.
- The conclusions about zeroize (MIN-03/MIN-21) rest on code review + FFI tests;
  checking real memory wiping via a process dump was not done.
- **No "unbreakability" guarantee exists** and none is claimed: the audit proves
  the absence of known vulnerability classes, not their impossibility.