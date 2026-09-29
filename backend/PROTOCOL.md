# MIN Protocol — Frozen Specification (v4, Stage 0)

> Status: FROZEN for stages 0-3. Any change = bump PROTOCOL_VERSION + migration.
> Source: MIN technical specification v1.2 §5.2, §18, §19, §20, §42, §44.
> §0-§10 are normative. §11 is explanatory and may change without a version bump.
>
> **AUDIT MIN-17 (v2):** the Envelope version was raised `1 → 2`. The derivation
> of field 7 (`aad_commitment`) changed: keyless BLAKE3 → **keyed MAC**; the
> string-form prefix of the Contact Key also changed, `MIN1:` → `MIN2:`. The
> wire layout (the set and types of fields) did not change, so no data migration
> is required, but an old and a new client now diverge **explicitly**
> (`UnsupportedVersion`) rather than silently (commitment mismatch). There were
> no deployed peers at the time of the bump.
>
> **MIN-RED-26 / O-5 (v3):** the Contact Key version was raised `2 → 3`.
> A mandatory field `6` (`epoch`) was added to the Contact Key, the signature
> field moved to `7`, and `mailbox_id` is now derived as HKDF over
> `identity_public_key || LE64(epoch)` (§5), with the string form prefixed
> `MIN3:`. The point: an address is no longer permanent — the relay cannot link
> a whole account's activity under one identifier, and epoch rotation yields an
> independent (unlinkable) address. Envelope v1 is unchanged byte for byte.
>
> **RED-006 (v4, frame API 2):** the overall contract was raised to `4`, while
> the Contact Key stays at wire-v3 and the Envelope at wire-v1. Only the Frame
> API §10 changed: `Enqueue` now requires `sender_mailbox` + `sender_token`
> (keys 2, 3), and `target_mailbox`/`envelope`/`item_type` move to keys 4/5/6.
> The old 4-field Enqueue is rejected by the strict parser (`Malformed`); the
> relay verifies the sender token before decrementing the per-sender rate
> bucket. Re-deployed nodes and clients must be updated together: mixed
> versions cannot exchange Enqueue, while the other operations keep returning
> an explicit version error.

## 0. Constants

| Constant | Value |
|---|---|
| `PROTOCOL_VERSION` | `4` (overall contract; Contact Key v3 and Envelope v1 have independent wire versions) |
| Serialisation | CBOR, canonical mode (RFC 8949 §4.2 — deterministic encoding) |
| String encoding | base58btc (string forms only, not the wire) |
| Signature | Ed25519 |
| DH (prekeys) | X25519 |
| AEAD | XChaCha20-Poly1305 (24-byte nonce) |
| KDF | HKDF-SHA256, domain-separated |
| Frame API | `2` (Enqueue requires the sender mailbox/token) |
| Max envelope | 256 KiB |
| Max REQUEST | 16 KiB |

**Strict parsing rule** (spec §42): an unknown version, extra fields, a wrong
length or a wrong field type → `ProtocolError`, with no "guessing". Map key
order is strictly by increasing integer key; signatures are computed over
exactly those canonical bytes.

## 1. MessageType

| Code | Type | Purpose |
|---|---|---|
| `0x01` | `REQUEST` | First contact (spec §8.1). ≤16 KiB, short TTL |
| `0x02` | `MESSAGE` | An ordinary encrypted session message |
| `0x03` | `CONTROL` | Accept/Reject/Block/PrekeyRefresh and similar (spec §8.8) |
| `0x04` | `ACK` | Delivery state (not a cryptographic confirmation of content, spec §20) |

## 2. MIN Contact Key v3

String form: `MIN3:<base58btc(envelope_bytes)>`

CBOR envelope - a map with integer keys (strictly increasing):

| Key | CBOR type | Field |
|---|---|---|
| `1` | `u64` | `version` = 3 |
| `2` | `bstr[32]` | `identity_public_key` (Ed25519) |
| `3` | `bstr[16]` | `mailbox_id` (opaque rendezvous, spec §5.2) |
| `4` | `bstr[32]` | `signed_prekey_public` (X25519) |
| `5` | `u64` | `expiry` (unix seconds; `0` = no expiry) |
| `6` | `u64` | `epoch` - the address epoch (`>= 1`; rotation = current + 1) - MIN-26 |
| `7` | `bstr[64]` | `signature` = Ed25519(identity) over the canonical CBOR bytes of fields `1..6` |

A bare public key without rendezvous data is not a delivery route (spec §7).

## 3. Envelope v1 (wire format)

CBOR map (keys increasing):

| Key | Type | Field |
|---|---|---|
| `1` | `u64` | `version` = 1 |
| `2` | `u64` | `type` = MessageType |
| `3` | `u64` | `epoch` |
| `4` | `u64` | `seq` (monotonic, per session+direction) |
| `5` | `bstr[16]` | `sender_hint` (opaque; zeros allowed) |
| `6` | `bstr[16]` | `mailbox_hint` |
| `7` | `bstr[16]` | `aad_commitment` - a **keyed MAC** over the whole structure: `BLAKE3-keyed(KDF(session_id), canonical_header(without field 7) + ciphertext + "min-envelope-commitment/v1")[..16]`. AUDIT MIN-17: it was previously described as a keyless BLAKE3, which is not a MAC; it was changed to a keyed hash. The wire layout did not change (the same 16 bytes), only the derivation |
| `8` | `bstr[24]` | `nonce` (XChaCha20) |
| `9` | `bstr` | `ciphertext` (AEAD, associated data = the canonical header) |
| `10` | `u64` | `ttl_sec` |
| `11` | `u64` | `queue_class` (0 = normal) |

**Never included**: plaintext names, phone, e-mail, preview (spec §19).

## 4. Anti-replay / ordering (spec §20)

- `seq` is strictly monotonic per `(session, direction)`; a repeated `seq` is
  dropped and does not create a duplicate message.
- The skipped-message-key cap is **100**; beyond that the session becomes
  `SUSPICIOUS` rather than retrying forever.
- After 3 consecutive decryption failures the session becomes `SUSPICIOUS`
  (cooldown), without degrading into an infinite loop.

## 5. Mailbox identity derivation

```
mailbox_id = HKDF-SHA256(ikm = identity_public_key[32] || LE64(epoch),
                         salt = "MIN-MAILBOX-SALT-v1",
                         info = "mailbox-id-v1",
                         L = 16)
```

Domain-separated, opaque to the relay, contains no phone or e-mail (spec §6).

**MIN-26 (epoch rotation, v6/P5):** within an epoch the address is stable;
`epoch + 1` yields a new address (the domain is separated by `LE64(epoch)`
inside the ikm). On rotation the client must close the previous address and
reject an epoch rollback (`EpochRotated`): the old session does not stay alive,
and the relay sees two unlinkable mailboxes. `epoch = 0` does not exist
(fail-closed both in the parser and in the session binding).

## 6. MVP quotas (spec §8.7)

| Parameter | MVP value |
|---|---|
| REQUEST queue cap | 20 unresolved / mailbox |
| REQUEST TTL | 7 days |
| MESSAGE TTL | 14 days |
| Mailbox queue overall cap | 200 envelopes |

## 7. Transport framing (not HTTP semantics)

`frame = u32be(len) || payload`, `len <= 256 KiB`. Over Tor (onion) in the MVP.
The REST endpoints of spec §12.3 exist only as a test wrapper around the same
frames.


## 8. Beta policy (stage 4)

`ContactPolicy::AutoAccept` - a REQUEST is accepted automatically (beta).
`ContactPolicy::ManualInbox` - queue + manual accept (production). Both are
implemented as a trait substitution, with no change to the core.

## 9. Transport: the `min-tor` crate (stage 4)

The crate `crates/min-tor` is a wrapper over Arti
(https://gitlab.torproject.org/tpo/core/arti), Tor in Rust. The transport client
is designed as follows:

- **`TorTransport::new(config)`** - creates a client **without bootstrapping**
  (offline, non-blocking): the right constructor for iOS wake-up paths and
  pre-network validation. Bootstrap happens lazily on the first network use;
  directory docs are cached on disk (state/cache dirs from `config`).
- **`TorTransport::connect(config)`** - eager bootstrap (ready for traffic
  immediately), for tests and foreground scenarios.
- **`bootstrapped()`** - checks client readiness; a "lazy" client requires an
  explicit network call to start bootstrap.
- **`last_activity()`** - telemetry of last use (for the client's polling
  timers).

The **`frame = u32be(len) || payload`** semantics (§7) do not change: `min-tor`
is only frame delivery over onion, with no HTTP wrapper. The spec §12.3 REST is
a test wrapper around the same frames, not the transport.

## 10. Relay Frame API (stage 4, crates min-protocol + min-relay)

The production client-relay exchange path: frames per §7 (`u32be(len) ||
payload`), carrying canonical CBOR inside (strict parsing per §0: exactly the
expected key set in increasing order, strict types; otherwise reject). Types:
`min_protocol::frame_api`.
**Frame API v2 (RED-006):** `Enqueue` must present a registered `sender_mailbox`
and its `pull_token`; the relay verifies the token before decrementing the
per-sender rate bucket. The old 4-field `Enqueue` is rejected as `Malformed`.
This does not disclose the sender identity to the relay any further: the
mailbox and the bearer token are already its own credentials.

Requests (`FrameRequest`, key 1 = op):

| op | Operation | Map keys |
|---|---|---|
| 1 | Register (claim-once) | 1, 2=mailbox_id (tstr) |
| 2 | Enqueue | 1=op, 2=sender_mailbox (tstr), 3=sender_token (bstr[32]), 4=target_mailbox (tstr), 5=envelope (bstr <=256 KiB), 6=item_type (u64 1..3) |
| 3 | Pull | 1, 2=mailbox_id (tstr), 3=token (bstr[32]) |
| 4 | Ack | 1, 2=mailbox_id, 3=token, 4=item_ids (array tstr, <=200) |

Responses (`FrameResponse`, key 1 = status: 1=ok, 2=err; key 2 = data):

| op | ok data (data keys) | err codes |
|---|---|---|
| 1 | 1=epoch, 2=pull_token bstr[32] | 3=Conflict |
| 2 | 1=item_id, 2=expires_at | 4=NotFound, 5=RateLimited |
| 3 | 1=items: array of {1=item_id, 2=envelope bstr, 3=item_type, 4=arrived_at, 5=expires_at} | 1=NotFound, 2=Forbidden |
| 4 | 1=acked | 1=NotFound, 2=Forbidden |

Common err codes: 1=NotFound, 2=Forbidden, 3=Conflict, 4=BadRequest,
5=RateLimited, 6=Internal. An authorisation refusal (Forbidden/NotFound) does
not reveal the existence of a mailbox to outsiders. A malformed frame produces a
BadRequest err frame and does **not** drop the connection (no cheap DoS channel).

Relay server: a TCP frame server (`min_relay::frame_server::serve_frames`, port
3001 behind the onion service) is production; the spec §12.3 REST (port 3000)
is only a test wrapper using the same store logic.


## 11. Cryptographic flows (NON-NORMATIVE section: explanatory)

> This section is explanatory: it describes cryptography that is already
> implemented (min-session = libsignal PQXDH + Double Ratchet, min-device,
> min-recovery, min-storage) and **does not change the wire format**. Edits
> inside §11 do not require a PROTOCOL_VERSION bump (a bump is only for
> §0-§10).

Sources: crates/min-session/src/manager.rs, crates/min-device/src/lib.rs,
crates/min-recovery/src/lib.rs, crates/min-storage/src/lib.rs,
MIN/Services/KeychainService.swift.

### 11.1 Session keys: PQXDH

1. A generates a prekey bundle (SessionManager::generate_prekey_bundle):
   Ed25519 identity + X25519 SignedPreKey (signed by the identity) +
   OneTimePreKey + an ML-KEM-1024 Kyber prekey (signed by the identity). The
   bundle travels to B outside wire messages: via the Contact Key (§2, fields
   2/4) and min_ffi_session_bundle_*.
2. B calls init_session_with_contact_key(identity, peer, epoch, bundle):
   libsignal performs PQXDH (X25519 + ML-KEM-1024 hybrid) -> shared secret ->
   HKDF -> initial root key. The secret is identical on both sides
   mathematically (A from the private prekeys, B from the public ones); no keys
   are transmitted over the network.
3. From then on both sides hold Double Ratchet state (11.3).

### 11.2 First authenticated handshake

- Authentication = Ed25519 signatures: the identity signs the SignedPreKey and
  the Kyber prekey (verified at from_cbor); the Contact Key (§2) is signed by
  the identity as a whole; Envelope field 7 (§3) is a keyed MAC over the whole
  structure.
- Beta: ContactPolicy::AutoAccept (§8) - a REQUEST is accepted automatically;
  in production, ManualInbox (accept/reject/block, spec §8.8).
- Trust on first use: the identity is pinned at first contact; a later
  substitution is detected (the bundle signature will not match).

### 11.3 Key per message (Double Ratchet)

- encrypt()/decrypt() - the libsignal Double Ratchet: every frame is encrypted
  with a NEW message key from the chain (root -> chain -> message key); the
  chain key rotates on each incoming frame from the peer. No keys are
  transmitted over the network.
- `seq` (§3 field 4) is monotonic per session+direction; gaps are skipped
  message keys (the gap cap is RT-26); the AEAD nonce is never reused
  (XChaCha20).

### 11.4 Phone compromise

- Disk: min-storage - SQLite with row-level XChaCha20-Poly1305 (each record has
  its own nonce); the master key lives only in the iOS Keychain
  (kSecAttrAccessibleWhenUnlockedThisDeviceOnly, excluded from iCloud backup,
  KeychainService.swift; the Secure Enclave is not used). The session snapshot
  is authenticated with a keyed MAC and encrypted with the same key
  (`SessionManager::snapshot` / `restore`; `restore_checked` is not yet called
  by the app, because the revoke list is not integrated).
- Theft with the key: an attacker sees the conversation history of THIS device,
  but cannot read the peers' future messages (forward secrecy, 11.5) and cannot
  impersonate other devices (the identity never leaves the device).
- Device revocation is **not integrated in the MVP**. `min-device` can create
  and verify a `RevokeCertificate`, but the relay does not process
  certificates, `AppCore` does not store a revoke list and does not call
  `restore_checked`. It is therefore not possible to claim that a revoked
  device can no longer return. Until it is fully implemented (relay-side
  certificate verification, revocation state storage, address rotation and UI)
  this is only a library primitive.
- Full identity compromise (root + key export): epoch rotation (epoch + 1, §5)
  gives a new unlinkable address, and partners receive a new Contact Key. There
  is no remote wipe in the MVP.

### 11.5 Forward secrecy

- Double Ratchet: compromising the current message key reveals neither the
  past (chain keys are wiped after use) nor the future (the next ratchet is
  shifted by a DH with fresh ephemeral keys).
- PQXDH gives the handshake post-quantum protection: traffic intercepted now
  cannot be decrypted later even with a quantum computer (ML-KEM-1024).
- There is no ratchet code of our own - a hand-written ratchet is forbidden
  (crate docs).

### 11.6 Session recovery after offline

- The relay stores the queue: MESSAGE TTL 14 days (§6). After being offline the
  client does a pull (with pull_token, §10) and receives everything that
  accumulated.
- The Ratchet state survives an app restart: the snapshot (11.4) is restored
  with a MAC check (`SessionManager::restore`).
- Missed messages: skipped message keys up to the cap; a gap beyond the cap ->
  the session is marked suspicious and a repeated handshake is needed
  (PrekeyRefresh CONTROL, §1) - a desync does not stick silently.
- If offline for more than 14 days: the old messages are purged by the relay,
  new ones still arrive; the participants continue with a new chain.

### 11.7 Several devices for one user

- A full revoke workflow (relay-side certificate verification, revocation state
  storage, address rotation and UI) is **not implemented** in the MVP;
  `min-device` and `restore_checked` are isolated library primitives for future
  integration.
- MVP: one device = one identity. A second device is a separate identity (its
  own Contact Key/epoch), that is, a separate client to the relay.
- History sync between devices (linked devices, as in Signal) is NOT
  implemented in the MVP - a product decision for later (device linking); the
  wire does not need to change, but it is a new protocol level.