#!/usr/bin/env python3
"""E2E through a real onion service.

Runs the three DoD scenarios against a live node over SOCKS5 -> Tor -> .onion:3001:

  E2E-1  two clients: A to B delivery, ack, second pull empty, foreign token -> Forbidden;
  E2E-2  offline delivery: recipient connects later and collects everything that accumulated;
  E2E-3  replay: after ack the message does not arrive again; the relay does NOT deduplicate
         ciphertext (anti-replay is a client-side property, carried in the envelope: the relay has no keys);
         re-registering the same mailbox -> Conflict.

The transport is the same as in the production client: `u32be(len) || padded(payload)`.

Usage:
    python3 e2e_onion_check.py --onion <addr>.onion --socks 127.0.0.1:9050
    python3 e2e_onion_check.py --host 127.0.0.1            # loopback control

Exit code 0 = all checks passed.
"""
import argparse
import secrets
import sys
import time

from min_frame_client import (ITEM_MESSAGE, ITEM_REQUEST, Relay, RelayError,
                              req_enqueue, req_pull, req_register)

TICK = {"pass": 0, "fail": 0}


def check(cond: bool, label: str, extra: str = "") -> bool:
    if cond:
        TICK["pass"] += 1
        print(f"   PASS  {label}")
    else:
        TICK["fail"] += 1
        print(f"   FAIL  {label} {extra}")
    return cond


def expect_error(fn, code: int, label: str) -> bool:
    """Checks that the call returned an err frame with exactly the expected code."""
    try:
        fn()
    except RelayError as e:
        return check(e.code == code, label, f"(got {e.name}, expected {code})")
    except Exception as e:  # noqa: BLE001 — a test: any failure counts
        return check(False, label, f"(exception {e!r})")
    return check(False, label, "(no error raised)")


def e2e1_two_clients(mk, tag: str) -> None:
    """A to B: delivery, ack, no repeats, token protection."""
    print("[E2E-1] two clients: A to B over onion")
    a, b = mk(), mk()
    ma, mb = f"{tag}-A-{secrets.token_hex(3)}", f"{tag}-B-{secrets.token_hex(3)}"

    t0 = time.time()
    tok_a = a.register(ma)
    tok_b = b.register(mb)
    print(f"   register both: {time.time() - t0:.2f}s")
    check(len(tok_a) == 32 and len(tok_b) == 32, "32-byte pull_token for both")

    env = bytes([0xAB]) * 96
    t0 = time.time()
    item_id, expires = a.enqueue(mb, env, ITEM_MESSAGE)
    check(bool(item_id) and expires > time.time(), "enqueue from A to B accepted")
    print(f"   enqueue: {time.time() - t0:.2f}s")

    items = b.pull(mb, tok_b)
    check(len(items) == 1, "B received exactly 1 message", f"(got {len(items)})")
    if items:
        it = items[0]
        check(it[2] == env, "ciphertext arrived byte for byte")
        check(it[3] == ITEM_MESSAGE, "item type preserved (MESSAGE)")

    check(b.ack(mb, tok_b, [item_id]) == 1, "ack confirmed 1 message")
    check(len(b.pull(mb, tok_b)) == 0, "a second pull after ack is empty (no duplicates)")

    # The token is the only mailbox secret: a foreign or broken one must get Forbidden.
    expect_error(lambda: a.pull(mb, tok_a), 2, "foreign token on pull -> Forbidden")
    expect_error(lambda: b.pull(mb, b"\x00" * 32), 2, "broken token on pull -> Forbidden")

    # An unknown mailbox gives NotFound, not a leak of its existence.
    expect_error(lambda: b.pull(f"{tag}-nope-{secrets.token_hex(2)}", tok_b),
                 1, "unknown mailbox -> NotFound")


def e2e2_offline_delivery(mk, tag: str) -> None:
    """Recipient offline: the queue accumulates, then is handed out in full."""
    print("[E2E-2] offline delivery: recipient connects later")
    sender, receiver = mk(), mk()
    sender_mb = f"{tag}-OFF-SND-{secrets.token_hex(3)}"
    mb = f"{tag}-OFF-{secrets.token_hex(3)}"
    sender.register(sender_mb)
    tok = receiver.register(mb)

    payloads = [f"offline-{i}".encode() * 8 for i in range(3)]
    ids = []
    for p in payloads:
        item_id, _ = sender.enqueue(mb, p, ITEM_MESSAGE)
        ids.append(item_id)
    check(len(set(ids)) == 3, "the three messages got different item_ids")
    print("   recipient offline: 3 messages queued")

    items = receiver.pull(mb, tok)
    check(len(items) == 3, "after connecting, all 3", f"(got {len(items)})")
    got = {it[2] for it in items}
    check(got == set(payloads), "contents of all three match")

    check(receiver.ack(mb, tok, ids) == 3, "ack confirmed all 3")
    check(len(receiver.pull(mb, tok)) == 0, "queue is empty after ack")

    # The REQUEST type lives in a separate quota (first-contact anti-spam, spec 8.7).
    item_id, _ = sender.enqueue(mb, b"hello-request", ITEM_REQUEST)
    items = receiver.pull(mb, tok)
    check(len(items) == 1 and items[0][3] == ITEM_REQUEST,
          "REQUEST message delivered and typed")
    receiver.ack(mb, tok, [item_id])


def e2e3_replay(mk, tag: str) -> None:
    """Replay: relay behaviour versus client-side protection (the relay has no keys)."""
    print("[E2E-3] replay over the real network")
    sender, receiver = mk(), mk()
    sender_mb = f"{tag}-REP-SND-{secrets.token_hex(3)}"
    mb = f"{tag}-REP-{secrets.token_hex(3)}"
    sender.register(sender_mb)
    tok = receiver.register(mb)

    env = b"replay-me-0123456789" * 2
    id1, _ = sender.enqueue(mb, env, ITEM_MESSAGE)

    # 1) A second enqueue of the SAME ciphertext: the relay cannot tell it apart
    #    (anti-replay is inside the envelope, keys are client-side only, spec 38),
    #    so a separate message is created with a new item_id. We record this as an
    #    expected property, not a bug: the recipient decides what to do with the duplicate.
    id2, _ = sender.enqueue(mb, env, ITEM_MESSAGE)
    check(id1 != id2, "duplicate ciphertext = separate item (the relay does not deduplicate)")
    check(len(receiver.pull(mb, tok)) == 2, "both messages are handed out (the decision is the client's)")

    # 2) A second pull WITHOUT ack creates no copies: the same item_ids, no more.
    items = receiver.pull(mb, tok)
    check(sorted(it[1] for it in items) == sorted([id1, id2]),
          "a second pull returns the same item_ids (the count does not grow)")

    # 3) ack is idempotent in state and retry-friendly in the counter: a repeated
    #    ack confirms the same item_ids with the same number (a client that re-acks
    #    after a timeout must not conclude the message was lost) and does NOT
    #    resurrect messages in the queue.
    check(receiver.ack(mb, tok, [id1, id2]) == 2, "ack of both messages")
    check(receiver.ack(mb, tok, [id1, id2]) == 2,
          "a repeated ack returns the same 2 (idempotent, retry-friendly)")
    check(len(receiver.pull(mb, tok)) == 0, "a second pull after ack is empty")

    # 4) Re-registering the same mailbox -> Conflict (name takeover).
    expect_error(lambda: mk().register(mb), 3, "re-register -> Conflict")


def main() -> int:
    ap = argparse.ArgumentParser(description="E2E over onion")
    ap.add_argument("--onion", help="onion service address (without :port)")
    ap.add_argument("--host", help="direct relay address (loopback control)")
    ap.add_argument("--port", type=int, default=3001)
    ap.add_argument("--socks", default="127.0.0.1:9050", help="SOCKS5 for onion")
    ap.add_argument("--timeout", type=float, default=120.0, help="per-frame timeout")
    ap.add_argument("--tag", default="E2E", help="mailbox_id prefix (uniqueness)")
    args = ap.parse_args()

    if not args.onion and not args.host:
        ap.error("need --onion <addr>.onion or --host <addr>")

    socks = None
    dest = (args.host or args.onion, args.port)
    if args.onion:
        shost, _, sport = args.socks.partition(":")
        socks = (shost, int(sport or 9050))
        print(f"transport: SOCKS5 {args.socks} → {args.onion}:{args.port}")
    else:
        print(f"transport: direct TCP → {args.host}:{args.port} (control)")

    def mk() -> Relay:
        return Relay(dest=dest, socks=socks, timeout=args.timeout)

    t0 = time.time()
    print(f"warming the Tor circuit: the first frame over onion may take 10-40s")
    e2e1_two_clients(mk, args.tag)
    e2e2_offline_delivery(mk, args.tag)
    e2e3_replay(mk, args.tag)
    dt = time.time() - t0

    total = TICK["pass"] + TICK["fail"]
    verdict = "PASS" if TICK["fail"] == 0 else f"FAIL ({TICK['fail']})"
    print(f"\nE2E RESULT: {verdict} — {TICK['pass']}/{total} checks, {dt:.1f}s")
    return TICK["fail"]


if __name__ == "__main__":
    sys.exit(main())
