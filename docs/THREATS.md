# Threat model: what MIN protects, and what it does not

This answers "what happens if someone gets hold of the phone" with concrete
scenarios. Each one was checked against the code and, where possible, on a live
test rig.

Read it honestly: there are sections below where MIN **does not protect you**.
Those are not typos, they are the boundaries of the current MVP.

## Protected by construction

| Mechanism | Where | Status |
|---|---|---|
| Conversation history in the database | row-level XChaCha20-Poly1305 | working, verified |
| Offline cache of the chat list | AES-GCM, key in the Keychain | fixed during the audit (was plaintext) |
| Database WAL/SHM | inherit row encryption | verified: 0 readable messages |
| Identity/device keys | iOS Keychain, `ThisDeviceOnly` | working |
| Message content in logs | not logged | verified |
| Private keys in the unified log | not logged (MIN-RED-008) | working |

## Scenarios

### 1. Someone takes the phone out of your hands, phone unlocked

**What leaks:** whatever is on screen. When the app is backgrounded, iOS takes a
snapshot and writes it to `Library/SplashBoard/Snapshots`, so the conversation
lands in a file even with the app closed.

**Status: screen hiding deliberately deferred.** This is not a hole but a future
configurable feature: Face ID, per-chat passwords and snapshot control are on
the plan. Until then the honest answer to a user is that the app does not hide
its contents from someone holding an unlocked phone.

### 2. Phone seized, locked

**What leaks:** the data on disk, but it is under a key in the Keychain, and iOS
will not let anything read the Keychain without an unlock.

**Status: partially protected.** The conversation on disk is encrypted (verified
by reading the container files), the keys are in the Keychain. Brute-forcing the
passcode is outside the app: a 6-digit code plus the Secure Enclave makes mass
guessing impractical, but not impossible under seizure.

### 3. Virus or malware on the device

**What leaks:** everything the app displays, and — while there is no biometrics
gate on the Keychain — the database key itself, which means the whole
conversation.

**Full protection is impossible:** code inside the process sees everything the
process holds in memory. But "impossible" does not mean "nothing to do". What
actually limits the damage:

| Measure | Status |
|---|---|
| Database key under `kSecAccessControl` with biometrics — malware cannot take the key silently | **not done, this is the main gap** |
| `zeroize` of buffers at the FFI boundary before free | done (MIN-03/21) |
| The key is not held in memory permanently but taken per operation | partial |
| Message text never written to logs or crash reports | done |
| Data files and the Tor directory excluded from backup | done |

Conclusion: the main lever against malware is **not code, it is a second factor
on the key**. Without it, malware running in the process is equivalent to full
access to the conversation.

### 4. Agencies seize the phone while it is unlocked

**What leaks:** the same as scenario 1, plus the ability to take the container
files. The conversation on disk is encrypted, but the app can reach the keys in
the Keychain, so on an unlocked phone the keys can be extracted and the whole
conversation read.

### 5. Forensic analysis of a powered-off or locked phone

**What leaks:** attempting to extract memory or the filesystem may give partial
access to cold memory.

**Status: not verified.** The container files are encrypted, but a proper
forensic analysis of memory has not been investigated.

### 6. iCloud backup or a local copy

**What leaks:** the backup contains the app container. The conversation and the
cache are encrypted with a Keychain key, and Keychain keys are **not** backed up
to iCloud (standard iOS behaviour for `ThisDeviceOnly`), so a single backup does
not reveal the conversation.

**Status: protected**, provided the backup was not taken from an already-unlocked
device. The app data directory and the Tor directory are explicitly excluded
from backup.

### 7. An order: "hand over the keys"

**What leaks:** anything that allows decrypting the conversation.

**Status: partially protected.** The relay holds no keys and cannot hand them
over — verified, it only ever sees ciphertext. But the keys on the device can be
handed over under seizure, and the app has no protection against coercion and
cannot have any: that is a platform limit. The practical conclusion is that the
"they took me or they took the phone" scenario needs external protection, not
encryption.

### 8. Compromised relay

**What leaks:** the fact of an exchange, mailbox addresses, timing, size class.
Not the content.

**Status: content protected.** Verified on a live onion: the relay receives only
ciphertext, and public keys and names are never transmitted at all. The metadata
is a known limitation, not a defect.

**Worth stating separately because it is often misunderstood:** the operator sees
no nicknames and does not know who the addresses are. The operator sees
`A → B` at 12:37. That cannot be linked to real people from the traffic alone,
but a full social graph can be computed, because the addresses are deterministic
and long-lived. One-time addresses and several independent relays are scaling
work, see `docs/ROADMAP.md`.

### 9. Compromised channel (Wi-Fi, ISP)

**Status: protected.** Transport goes over Tor/onion, the content is hidden, and
the traffic is indistinguishable by content.

### 10. Lost device, backup available

**Status:** the same as scenario 6 — the conversation is not recoverable from
the backup and the key stays on the device. This is deliberate: copying the key
into the backup would mean the whole archive is readable if the backup is stolen.

### 11. Former colleague, or anyone with device access

**What leaks:** the state of the device at the moment they left — conversation,
contacts, identity. Device revocation is **not integrated** in the MVP, a known
gap: a compromised device formally stays trusted.

**Status: NOT PROTECTED.** One of the main gaps of the MVP.

## How a device actually "hands over keys"

The mechanism, so that "hands over" is not confused with "was stolen":

1. **The device hands over nothing.** No backdoor, no copy of the key on the
   server, no export. The relay has no keys at all — verified on a live onion.
2. The key sits in the iOS Keychain with the class `WhenUnlockedThisDeviceOnly`.
   Such an item:
   - is readable **only on an unlocked device**;
   - **never enters an iCloud backup**;
   - is protected by the passcode key, so it cannot be read from a locked phone
     without the passcode.
3. What **can** read the key: code running **as the app** — malware inside the
   MIN process, a compromised dependency, or a forensic tool on an unlocked phone
   with a known passcode.

**The key point:** only `kSecAttrAccessible` is set, without `kSecAccessControl`
carrying biometrics. That means **an unlocked phone equals handed-over keys** —
not because of a bug, but because no second factor has been set.

### Why this matters specifically for Face ID

What is needed is `kSecAccessControl` with `biometryCurrentSet` (or
`.devicePasscode`). Then malware inside the process cannot take the key
silently — reading it triggers a system confirmation prompt; re-enrolling a new
face invalidates the item; and the key never leaves the Secure Enclave without a
human.

This has to be said **before** Face ID is implemented: an in-app lock screen is
cosmetic, because any app code can bypass it. `kSecAccessControl` is enforced by
the iOS kernel and cannot be bypassed from inside the app. "Face ID in MIN" is
therefore worth exactly as much as it is built into the Keychain, and not one
line more as a drawn overlay on top of a chat.

## Summary for the reader

| Scenario | Content | Identity |
|---|---|---|
| Phone taken, unlocked | **leaks** (screen hiding is planned) | leaks |
| Seized, locked | protected | protected |
| Malware inside the app | **leaks** | **leaks** |
| Order + unlocked phone | **leaks** | **leaks** |
| Backup without the device | protected | protected |
| Compromised relay | protected | protected |
| Network interception | protected | protected |
| Device revocation | — | **not protected** |

## What to close first

1. **`kSecAccessControl` with biometrics on the database key** — the only measure
   that actually stands in the way of both in-process malware and seizure of an
   unlocked phone. Do it together with Face ID, otherwise Face ID is cosmetic.
2. **Device revocation** — closes the "former colleague" case and a lost device
   that keeps its access.
3. **Screen hiding on backgrounding** — planned as a configurable feature
   together with per-chat passwords; no separate urgency.
4. Honest wording in the product: on an unlocked phone the conversation can be
   read. That has to be said to the user explicitly.