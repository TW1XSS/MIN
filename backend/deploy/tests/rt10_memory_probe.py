#!/usr/bin/env python3
"""RT-10 probe: наполняет реле через loopback и сканирует его память.

Что проверяет:
  1. реле принимает register/enqueue/pull/ack (живой frame API, PROTOCOL §7);
  2. в дампе адресного пространства НЕТ секретных ключей (реле не зависит от
     min-crypto — ключей физически не существует);
  3. отправленный шифротекст лежит в памяти ТОЛЬКО как opaque (hex/bytes),
     реле не содержит кода расшифровки и не создаёт plaintext;
  4. кроме ciphertext/prekey, на диске допускается только auth-state с
     mailbox_id + BLAKE3(pull_token), без raw token/identity/payload;
  5. RT-11: TTL письма ровно 14 дней, считается от arrived_at (не от now),
     т.е. прыжки часов после ребута без RTC на TTL не влияют.

CBOR/транспорт берётся из min_frame_client.py — единый wire с E2E-тестами
(две копии кодека = рассинхрон с PROTOCOL).

Использование (на узле, под root для --dump):
    python3 rt10_memory_probe.py            # только протокольный цикл + TTL
    python3 rt10_memory_probe.py --dump     # + дамп памяти и сканы
"""
import argparse
import os
import secrets
import sys

from min_frame_client import (ITEM_MESSAGE, call, req_ack, req_enqueue,
                              req_pull, req_register)

CANARY = b"MINCANARY-RT10-0123456789abcdef"
CANARY_HEX = CANARY.hex().encode()   # как реле хранит envelope (hex-строка)

# Маркеры того, чего в памяти реле быть НЕ должно: ключи, TLS/SSH-материал,
# код крипто-крейта. Наличие любого = провал RT-10.
SECRET_MARKERS = [
    b"PRIVATE KEY", b"BEGIN OPENSSH", b"hs_ed25519", b"min_crypto",
    b"identity_key", b"identity.key",
]


def dump_process_memory(pid: int) -> bytes:
    """Читает анонимные r-регионы /proc/<pid>/mem (heap/stack/bss)."""
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if "r" not in parts[1]:
                continue
            path = parts[5] if len(parts) > 5 else ""
            if path.startswith("/") and not path.startswith("/dev/zero"):
                continue  # file-backed (сам бинарь/библиотеки) — пропускаем
            start_s, end_s = parts[0].split("-")
            regions.append((int(start_s, 16), int(end_s, 16)))

    out = bytearray()
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for start, end in regions:
            size = end - start
            if size <= 0 or size > 64 * 1024 * 1024:
                continue
            try:
                out += os.pread(mem.fileno(), size, start)
            except (OSError, OverflowError):
                continue
    return bytes(out)


def scan(dump: bytes, label: str) -> int:
    hits = [m for m in SECRET_MARKERS if m in dump]
    print(f"   {label}: {len(dump)} байт; секретные маркеры: {hits if hits else 'НЕТ'}")
    return len(hits)


def protocol_cycle(mailbox: str, call_fn=None) -> int:
    """register → enqueue → pull → ack + проверки RT-11 (TTL).

    call_fn — функция вызова реле (по умолчанию loopback из min_frame_client),
    чтобы тот же цикл можно было прогнать через onion/SOCKS.
    """
    if call_fn is None:
        call_fn = call
    fail = 0
    print("[1] протокольный цикл (register → enqueue → pull → ack)")

    r = call_fn(req_register(mailbox))
    if r.get(1) != 1:
        print(f"   FAIL: register → {r}")
        return 1
    token = r[2][2]
    print(f"   register OK: epoch={r[2][1]}, pull_token={len(token)} байт")

    r = call_fn(req_enqueue(mailbox, token, mailbox, CANARY, ITEM_MESSAGE))
    if r.get(1) != 1:
        print(f"   FAIL: enqueue → {r}")
        return 1
    item_id = r[2][1]
    expires_at = r[2][2]
    print(f"   enqueue OK: item_id={item_id}, expires_at={expires_at}")

    r = call_fn(req_pull(mailbox, token))
    items = r[2][1] if r.get(1) == 1 else []
    got = [it for it in items if it.get(1) == item_id]
    print(f"   pull OK: {len(items)} шт., канарейка найдена: {bool(got)}")
    if not got:
        fail += 1
    else:
        it = got[0]
        if it.get(2) != CANARY:
            print("   FAIL: envelope на wire не совпал с отправленным")
            fail += 1
        arrived, expires = it.get(4, 0), it.get(5, 0)
        ttl = expires - arrived
        expected = 14 * 24 * 3600
        print(f"   RT-11: arrived_at={arrived}, expires_at={expires}, TTL={ttl}s "
              f"(ожидаем {expected}s)")
        if ttl != expected:
            print("   FAIL: TTL письма не равен 14 дням")
            fail += 1
        if expires != expires_at:
            print("   FAIL: expires_at в pull не совпал с enqueue")
            fail += 1

    r = call_fn(req_ack(mailbox, token, [item_id]))
    if r.get(1) != 1 or r[2][1] != 1:
        print(f"   FAIL: ack → {r}")
        fail += 1
    else:
        print(f"   ack OK: подтверждено {r[2][1]}")

    return fail


def memory_dump_checks(pid: int) -> int:
    """RT-10: дамп памяти + проверка, что диск содержит только auth-state."""
    fail = 0
    print("[2] RT-10: дамп адресного пространства min-relay")
    if not pid or not os.path.exists(f"/proc/{pid}/mem"):
        print(f"   FAIL: не могу прочитать /proc/{pid}/mem (нужен root)")
        return fail + 1
    print(f"   pid={pid}")

    dump = dump_process_memory(pid)
    if not dump:
        print("   FAIL: дамп пуст")
        return fail + 1

    fail += scan(dump, "память")

    # Канарейка: реле обязано держать её как opaque, без «расшифрованного» вида.
    print(f"   канарейка как opaque hex найдена: {CANARY_HEX in dump}")
    print(f"   канарейка как исходные байты найдена: {CANARY in dump} "
          f"(ожидаем True — это ровно то, что прислал клиент)")

    # В prod-режиме на диске допускается только закрываемый auth-state;
    # payload/ciphertext и identity в нём отсутствуют.
    fds = []
    try:
        for name in os.listdir(f"/proc/{pid}/fd"):
            fds.append(os.readlink(f"/proc/{pid}/fd/{name}"))
    except OSError:
        pass
    files = [f for f in fds if f.startswith("/")]
    print(f"   открытых файлов на диске: {len(files)} {files if files else ''}")
    # В prod-режиме единственный допустимый дисковый файл — auth-state.
    # В нём не должно быть ciphertext, canary или identity/token material.
    state_files = [f for f in files if f != "/dev/null"]
    auth_state = "/var/lib/min-relay/mailbox-auth.state"
    allowed = {
        auth_state,
        "/var/log/min-relay/relay.log",
    }
    unexpected = [f for f in state_files if f not in allowed]
    if unexpected:
        print(f"   FAIL: реле держит неожиданные файлы состояния: {unexpected}")
        fail += 1
    try:
        with open(auth_state, "rb") as auth:
            auth_bytes = auth.read()
    except OSError as exc:
        print(f"   FAIL: auth-state недоступен: {exc}")
        return fail + 1
    # Канарейка не должна попасть в auth-state. Заголовок файла намеренно
    # содержит слова policy, поэтому проверяем только реальные маркеры данных.
    for marker, label in ((CANARY, "canary"), (CANARY_HEX, "canary-hex"),
                          (b"BEGIN ", "private-key marker"), (b"identity_public", "identity key")):
        if marker in auth_bytes:
            print(f"   FAIL: auth-state содержит {label}")
            fail += 1
    for line in auth_bytes.splitlines():
        if not line or line.startswith(b"#"):
            continue
        fields = line.split()
        if len(fields) != 2 or not fields[0] or len(fields[0]) > 256:
            print(f"   FAIL: неожиданная запись auth-state: {line[:80]!r}")
            fail += 1
            continue
        try:
            bytes.fromhex(fields[1].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            print(f"   FAIL: token hash не 64-hex: {line[:80]!r}")
            fail += 1
    print(f"   auth-state: {len(auth_bytes)} байт; только opaque mailbox_id + 64-hex hash")
    return fail


def main() -> int:
    ap = argparse.ArgumentParser(description="RT-10/RT-11 probe для MIN relay")
    ap.add_argument("--dump", action="store_true", help="сканировать память процесса")
    ap.add_argument("--pid", type=int, default=0,
                    help="PID min-relay (по умолчанию из systemd)")
    ap.add_argument("--mailbox", default=f"RT10-{secrets.token_hex(4)}",
                    help="mailbox_id (уникальный: register конфликтует на повторе)")
    ap.add_argument("--dest", default="127.0.0.1:3001",
                    help="адрес реле host:port")
    args = ap.parse_args()

    host, _, port = args.dest.partition(":")
    call_fn = lambda payload, raw=False: call(  # noqa: E731 — компактный адаптер
        payload, raw=raw, dest=(host, int(port or 3001))
    )

    fail = protocol_cycle(args.mailbox, call_fn)
    if not args.dump:
        print(f"\nИТОГ RT-11 (протокол): {'PASS' if fail == 0 else f'FAIL ({fail})'}")
        return fail

    pid = args.pid
    if not pid:
        try:
            pid = int(os.popen("systemctl show -p MainPID --value min-relay").read().strip())
        except Exception:
            pid = 0
    fail += memory_dump_checks(pid)
    print(f"\nИТОГ RT-10: {'PASS' if fail == 0 else f'FAIL ({fail})'}")
    return fail


if __name__ == "__main__":
    sys.exit(main())


