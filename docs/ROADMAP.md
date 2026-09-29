# ROADMAP: from a working MVP to release

> Owner + BACK document. Updated as items close.
> Date: 2026-09-28. Current phase: **MVP (live, over Tor/onion)**.

## 0. What this roadmap is

- It lists **only future work**, in priority order.
- The current state of the project and the working notes are kept in the
  internal project journal and are not part of the public export; this roadmap
  is not used as a record of the past.
- A closed item moves to the internal journal as a single "done" line, or into
  measured security/release evidence.

## 1. MVP+ after the grant

- [ ] Speed up the first Tor start and reduce the time to app readiness.
- [ ] Automate the fallback transports and verify them independently of the
      primary channel; a user should not have to find bridges by hand.
- [ ] Add further relay nodes for resilience and for measuring delivery latency.
- [ ] Extend the E2E regression harness: offline, relay restart, redelivery and
      transport fallback.
- [ ] Update every peer client for frame API v2: `Enqueue` requires the sender
      mailbox/token, and the old format is rejected with an explicit error, so
      this needs a controlled rollout of relay and clients with no silent
      delivery loss.
- [ ] Test a separate abuse/Sybil layer: a registered sender must not be able to
      fill one target's queue indefinitely. Entitlement and access control are
      designed separately from the free baseline.

## 2. Release 1 - safe exchange and permanent clients (1-2 months)

- [ ] **A one-time short invite ID** instead of the bulky `MIN3+BND`: usable on
      paper or as a QR code, with the relay storing only opaque ciphertext and
      technical state, claim-once and TTL. This is a wire change: design review
      first, then a `PROTOCOL_VERSION` bump and a migration decision.
- [ ] **Nickname / `@username` lookup** without a permanent global identifier:
      a separate threat model, rotating or opaque rendezvous, or an onion
      directory with rate limiting.
- [ ] **Minimal statuses** sent/delivered, without read receipts or typing leaks.
- [ ] **Push wake-up**, decided on the anonymity-versus-latency trade-off:
      zero-push, or coalesced generic notifications with no content.
- [ ] **Limits and monetisation**: the free basic tier stays; a paid tier can
      offer larger per-mailbox queues, TTL, storage and media. The entitlement
      is signed, carries no identity, and "unlimited" is not promised without a
      cost, abuse and multi-relay model.
- [ ] A **red-team client agent** on the same FFI, with access to the core audit.
- [ ] **First message from a stranger** ("you have my invite, so you can write
      to me, I never entered yours"). Not possible today: the session is
      initialised via `init_session_with_contact_key(peer bundle)`, while the
      incoming envelope (§3) carries only `sender_hint`/`mailbox_hint` - the
      sender's prekey is not transmitted, so a shared secret cannot be derived
      without the bundle. Needed: (1) the first message carries a signed
      identity prekey bundle of the sender; (2) the recipient creates the
      session straight from the message; (3) the message lands in **requests**
      (`REQUEST`, spec §8.1) with an explicit Accept/Reject/Block, not straight
      into a chat. No auto-accept - that is precisely the spam vector we defend
      against. Wire change, so `PROTOCOL_VERSION` gets bumped.

## 3. Release candidate and platforms (3-6 months)

- [ ] An Android client on the same Rust core; then macOS, Windows and Linux
      UI/FFI targets.
- [ ] Multi-device, encrypted recovery and several relay nodes for resilience.
- [ ] An independent external audit of the client, relay and protocol, after the
      internal self-hack is done and the security evidence is published.
- [ ] Bots, groups, channels, E2E media; calls are a separate, later stage, after
      an audit of the WebRTC/onion transport.
- [ ] **Hiding message length from the relay.** Today the relay knows the exact
      size of every envelope: it has to parse the CBOR request, and a `bstr`
      states its length explicitly. Size-class padding hides the size from a
      channel observer but not from the relay. This needs a real architectural
      rework (for example an opaque fixed-size container with an inner structure
      under an additional AEAD), not a cosmetic fix.
- [ ] **Unlinkability of sender and recipient.** The relay sees no names and no
      public keys, only addresses, and those are already opaque — but an
      `Enqueue` frame carries `sender_mailbox` and `target_mailbox` together,
      and the address is deterministic (`HKDF(identity ‖ epoch)`). The operator
      can therefore build the full "who to whom, when, how often" graph and
      link a person's entire conversation history over time. This cannot be
      fixed on a single relay: by definition it sees both sides. What is needed
      is several independent relay nodes (the recipient holds addresses at
      several operators, the sender picks a subset per message), one-time
      addresses instead of deterministic ones, and a decision on delivery
      receipts — those confirm the link too. This belongs to the server-scaling
      stage; it touches `PROTOCOL.md` §6-§7, so it needs a protocol version.
      The detailed risk model is in `docs/THREATS.md`.

## 4. Deferred decisions (nickname, monetisation, blockchain)

1. **Name/nickname and public key.** The current invite is large and meant to
   be copied; it is not a short `@monk`. A short invite, QR and a
   rotating/opt-in username are a separate design exercise after the MVP.
2. **Push.** APNs exposes the IP/token. Zero-push first, then coalesced generic
   notifications with no content if latency demands it.
3. **Limits and revenue.** A queue of 200 messages / 14 days is an
   anti-abuse and operational cap, not a "physically impossible" limit. A paid
   tier can raise queue/TTL/storage, but the free basic tier must not
   disappear; bypassing limits through new mailboxes or relays without an auth
   and abuse model is not allowed.
4. **Blockchain / wallet (deferred research, not MVP).** A proprietary L1
   sharply increases the crypto-audit, legal, energy and regulatory risks. First
   a messenger, stable users and revenue; then an existing proven chain as an
   opt-in. A proprietary chain is a separate decision with its own threat
   model, audit and funding.

## 5. Monetisation and limits

The current relay has technical caps: 20 REQUEST, 200 MESSAGE per mailbox, a TTL
of 7/14 days, a 256 KiB frame cap and a rate limiter. This is anti-abuse and
DoS protection, not a proven product limitation. Simply "lifting the cap" is not
possible: without a cost, abuse and multi-relay model it brings back spam, RAM
exhaustion and unpredictable cost.

The first paid layer, after stabilisation:

- the free baseline keeps working and does not disappear when the cap is hit;
- a paid entitlement can raise queue/TTL and add secure storage and media, but
  the entitlement is signed by the server/relay and carries no identity, no
  plaintext and no advertising profile;
- "unlimited" is not promised before multi-relay, quotas and abuse control;
- billing and entitlement are **not implemented yet** and remain release work.

## 6. Platforms and deferred products

- [ ] An Android client on the shared Rust core.
- [ ] macOS, Windows and Linux UI/FFI targets after iOS/iPadOS stabilise.
- [ ] Groups, channels and bots — after the basic 1-to-1 model and abuse control.
- [ ] E2E media and calls — only after a separate design review; calls are not
      in the MVP and require a separate transport/STUN/TURN audit.
- [ ] Proper device revocation: the relay verifies the certificate and stores
      revocation state, the client uses `restore_checked`; today only the
      primitives exist.

Blockchain and a built-in wallet are not in the MVP and not a commitment. A
proprietary L1 would bring a separate crypto audit, legal, financial and
regulatory risk. What is needed first is a messenger, users and revenue; an
opt-in integration with an existing proven network can come later. A proprietary
chain only after a threat model, funding and an audit.

## 7. Nickname, invite and the paper scenario

The current `MIN3+BND` invite is long, but it safely carries the encrypted
contact/prekey data. It is not a short `@username`, it is not a QR code, and it
implements no global search. A short invite and QR UX are post-MVP work.

A separate future topic:

- a short one-time code for paper, QR or an ordinary messenger;
- a rotating or opt-in username, so a nickname never becomes a permanent public
  identifier;
- onion/blinded lookup with rate limiting, with no global index and no logs of
  content or identity.

Until the threat model is complete, QR or a full invite is safer than a global
search over a permanent nickname.


- Each phase = a closed E2E loop: client to client over onion, proven by a test.
- Commits are topical, the history is linear.
- The backlog is this file; checkbox states follow the closing of items.
