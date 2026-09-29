#!/usr/bin/env python3
"""Минимальный клиент frame API (PROTOCOL §7) для deploy-тестов.

Зачем отдельный модуль: и RT-10 (dump-тест памяти), и E2E через onion
(e2e_onion_check.py) говорят на одном wire-формате. Держать две копии CBOR
нельзя — рассинхрон тестов с PROTOCOL дороже, чем один импорт.

Что внутри:
  * canonical CBOR (подмножество, ровно под frame_api): целые ключи по
    возрастанию, definite-length — как min_protocol::canonical_encode;
  * padding по классам min_net::pad_payload (клиент обязан паддить);
  * транспорт `u32be(len) || payload`, ответ читается целиком;
  * SOCKS5-диалер: чтобы ходить на `.onion:3001` без внешних зависимостей
    (тесты запускаются и на Pi, и с Mac, и на голом Debian).

В production эти тестовые скрипты не устанавливаются.

Использование:
    from min_frame_client import Relay, REQ_MESSAGE
    r = Relay()                                   # 127.0.0.1:3001
    r = Relay(dial=("onion", 3001), socks=("127.0.0.1", 9050))
    token = r.register("MBOX")
    item = r.enqueue("MBOX", b"\\x01\\x02")
    items = r.pull("MBOX", token)
"""
import random
import socket
import struct

# --- canonical CBOR: энкодер -------------------------------------------------

def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)


def cint(n: int) -> bytes:
    return _head(0, n)


def ctext(s: str) -> bytes:
    b = s.encode()
    return _head(3, len(b)) + b


def cbytes(b: bytes) -> bytes:
    return _head(2, len(b)) + b


def cmap(pairs) -> bytes:
    out = _head(5, len(pairs))
    for k, v in pairs:
        out += k + v
    return out


# --- canonical CBOR: минимальный декодер (разбор ответов) --------------------

def _dec(buf: bytes, i: int):
    ib = buf[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        n = info
    elif info == 24:
        n = buf[i]; i += 1
    elif info == 25:
        n = struct.unpack_from(">H", buf, i)[0]; i += 2
    elif info == 26:
        n = struct.unpack_from(">I", buf, i)[0]; i += 4
    else:
        raise ValueError("indefinite/unsupported CBOR")
    if major == 0:
        return n, i
    if major == 2:
        return buf[i:i + n], i + n
    if major == 3:
        return buf[i:i + n].decode(), i + n
    if major == 4:
        arr = []
        for _ in range(n):
            v, i = _dec(buf, i)
            arr.append(v)
        return arr, i
    if major == 5:
        m = {}
        for _ in range(n):
            k, i = _dec(buf, i)
            v, i = _dec(buf, i)
            m[k] = v
        return m, i
    raise ValueError(f"unsupported major {major}")


def decode(buf: bytes):
    """Разбор CBOR-значения из начала буфера (значение + конец не проверяем)."""
    v, _ = _dec(buf, 0)
    return v


# --- padding: те же классы, что min_net::pad_payload -------------------------
PADDING_CLASSES = (256, 512, 1024, 2048, 4096, 8192, 16384, 65536, 256 * 1024)


def pad(payload: bytes, rng) -> bytes:
    total = len(payload) + 2
    target = next((c for c in PADDING_CLASSES if c >= total), None)
    if target is None:
        raise ValueError("payload too large")
    buf = bytearray(struct.pack(">H", len(payload)) + payload)
    extra = (rng.randrange(target - total) if target > total else 0)
    tail = total + extra
    buf += bytes(rng.randrange(256) for _ in range(tail - total))
    buf += b"\x00" * (target - len(buf))
    return bytes(buf)


# --- SOCKS5 (только CONNECT, без аутентификации) -----------------------------
# Нужен для E2E через реальный onion: клиент MIN ходит так же, только своим
# Tor-стеком (crate min-tor).

def socks5_connect(socks_addr, host: str, port: int, timeout: float = 60.0) -> socket.socket:
    s = socket.create_connection(socks_addr, timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
        s.close()
        raise RuntimeError(f"SOCKS5 greeting failed: {resp!r}")
    h = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    head = s.recv(4)
    if len(head) != 4 or head[1] != 0:
        s.close()
        raise RuntimeError(f"SOCKS5 CONNECT failed: {head!r} (код {head[1] if len(head) > 1 else '?'})")
    atyp = head[3]
    if atyp == 1:
        s.recv(4 + 2)
    elif atyp == 4:
        s.recv(16 + 2)
    elif atyp == 3:
        n = s.recv(1)[0]
        s.recv(n + 2)
    return s


def dial(dest, socks=None, timeout: float = 60.0) -> socket.socket:
    if socks:
        return socks5_connect(socks, dest[0], dest[1], timeout=timeout)
    return socket.create_connection(dest, timeout=timeout)


# --- frame API ---------------------------------------------------------------

def call(payload: bytes, raw: bool = False, dest=("127.0.0.1", 3001), socks=None,
         timeout: float = 60.0, padded: bool = True):
    """Один кадр-запрос → один кадр-ответ. Возвращает разобранный CBOR."""
    body_out = pad(payload, random.Random()) if padded else payload
    s = dial(dest, socks=socks, timeout=timeout)
    try:
        s.sendall(struct.pack(">I", len(body_out)) + body_out)
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise RuntimeError("EOF at frame prefix")
            hdr += c
        n = struct.unpack(">I", hdr)[0]
        body = b""
        while len(body) < n:
            c = s.recv(n - len(body))
            if not c:
                break
            body += c
    finally:
        s.close()
    if raw:
        return body
    plen = struct.unpack_from(">H", body, 0)[0]
    return decode(body[2:2 + plen])


# --- запросы (PROTOCOL §7) ---------------------------------------------------
REQ_REGISTER, REQ_ENQUEUE, REQ_PULL, REQ_ACK = 1, 2, 3, 4
ITEM_REQUEST, ITEM_MESSAGE, ITEM_CONTROL = 1, 2, 3
ERR_NAMES = {1: "NotFound", 2: "Forbidden", 3: "Conflict", 4: "BadRequest",
             5: "RateLimited", 6: "Internal"}


def req_register(mailbox: str) -> bytes:
    return cmap([(cint(1), cint(REQ_REGISTER)), (cint(2), ctext(mailbox))])


def req_enqueue(sender_mailbox: str, sender_token: bytes, target_mailbox: str,
                envelope: bytes, item_type: int = ITEM_MESSAGE) -> bytes:
    return cmap([
        (cint(1), cint(REQ_ENQUEUE)),
        (cint(2), ctext(sender_mailbox)),
        (cint(3), cbytes(sender_token)),
        (cint(4), ctext(target_mailbox)),
        (cint(5), cbytes(envelope)),
        (cint(6), cint(item_type)),
    ])


def req_pull(mailbox: str, token: bytes) -> bytes:
    return cmap([(cint(1), cint(REQ_PULL)), (cint(2), ctext(mailbox)), (cint(3), cbytes(token))])


def req_ack(mailbox: str, token: bytes, item_ids) -> bytes:
    arr = _head(4, len(item_ids))
    for i in item_ids:
        arr += ctext(i)
    return cmap([
        (cint(1), cint(REQ_ACK)),
        (cint(2), ctext(mailbox)),
        (cint(3), cbytes(token)),
        (cint(4), arr),
    ])


# --- удобная обёртка для тестов ----------------------------------------------
class RelayError(RuntimeError):
    """Реле вернуло err-кадр (FrameResponse::Error)."""

    def __init__(self, code: int, op: str):
        self.code = code
        self.name = ERR_NAMES.get(code, f"Unknown({code})")
        super().__init__(f"{op}: реле вернуло {self.name}")


class Relay:
    """Клиент реле: dest=(host,port), socks=(host,port) для .onion.

    Бросает RelayError на err-кадр и RuntimeError на транспортную ошибку —
    тестам не нужно вручную разбирать статус каждого ответа.
    """

    def __init__(self, dest=("127.0.0.1", 3001), socks=None, timeout: float = 60.0):
        self.dest = dest
        self.socks = socks
        self.timeout = timeout
        self.sender_mailbox: str | None = None
        self.sender_token: bytes | None = None

    def call(self, payload: bytes, raw: bool = False):
        return call(payload, raw=raw, dest=self.dest, socks=self.socks,
                    timeout=self.timeout)

    @staticmethod
    def _ok(resp, op: str):
        # статус 1 = успех; 2 = Error { 1: 2, 2: code }
        if resp.get(1) == 2:
            raise RelayError(resp.get(2, 0), op)
        if resp.get(1) != 1:
            raise RuntimeError(f"{op}: неожиданный статус {resp}")
        return resp[2]

    def register(self, mailbox: str) -> bytes:
        body = self._ok(self.call(req_register(mailbox)), "register")
        self.sender_mailbox = mailbox
        self.sender_token = body[2]
        return body[2]                      # pull_token

    def register_full(self, mailbox: str):
        body = self._ok(self.call(req_register(mailbox)), "register")
        self.sender_mailbox = mailbox
        self.sender_token = body[2]
        return body[1], body[2]             # (epoch, pull_token)

    def enqueue(self, mailbox: str, envelope: bytes, item_type: int = ITEM_MESSAGE):
        if self.sender_mailbox is None or self.sender_token is None:
            raise RuntimeError("enqueue before register: sender auth is required")
        body = self._ok(self.call(req_enqueue(
            self.sender_mailbox, self.sender_token, mailbox, envelope, item_type,
        )), "enqueue")
        return body[1], body[2]             # (item_id, expires_at)

    def pull(self, mailbox: str, token: bytes):
        body = self._ok(self.call(req_pull(mailbox, token)), "pull")
        return body[1]                      # items: list of dicts

    def ack(self, mailbox: str, token: bytes, item_ids) -> int:
        body = self._ok(self.call(req_ack(mailbox, token, item_ids)), "ack")
        return body[1]                      # acked count

    def raw_error(self, payload: bytes):
        """Сырой ответ для негативных проверок (без исключений)."""
        return self.call(payload)

