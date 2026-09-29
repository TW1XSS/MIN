//! SOCKS5-линк: наш frame-протокол поверх Tor SOCKS (C Tor / Arti).
//!
//! Прод-путь iOS: приложение поднимает C Tor (Tor.framework) с мостами
//! (IPtProxy: obfs4/snowflake) — Tor слушает SOCKS на 127.0.0.1:9050; этот линк
//! открывает SOCKS5 CONNECT к `.onion:порт` и говорит по нашему frame-протоколу
//! (§7). Relay видит только выходной узел Tor — метаданные закрыты с обеих
//! сторон; провайдер видит только obfs4/snowflake-трафик к мосту.
//!
//! Паддинг: как в `tcp_link` — запрос/ответ паддируются (min-net size
//! classes). MIN-RED-011: это не скрывает длину от relay (CBOR `bstr`
//! несёт её явно), только от пассивного наблюдателя канала.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use min_net::{read_frame, unpad_payload, write_frame};
use rand_core::OsRng;

use crate::{DeliveryError, FrameExchange};

/// Кадр превышает лимит §7 — ошибка линка.
const MAX_FRAME: usize = 256 * 1024;

/// Первый коннект к onion через Tor может занимать десятки секунд.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(180);
/// Ответ relay на кадр: сеть Tor медленная, но не бесконечная.
const IO_TIMEOUT: Duration = Duration::from_secs(120);

pub struct SocksLink {
    /// Назначение: `host.onion:port` (резолвит Tor, не системный DNS).
    dest: String,
    /// Локальный SOCKS5 (C Tor/Arti), обычно 127.0.0.1:9050.
    socks: String,
    stream: Option<TcpStream>,
}

impl SocksLink {
    /// Соединение ленивое — устанавливается на первом `exchange` (Tor может
    /// ещё бустрапиться в момент создания линка).
    pub fn new(dest: impl Into<String>, socks: impl Into<String>) -> Self {
        Self {
            dest: dest.into(),
            socks: socks.into(),
            stream: None,
        }
    }

    fn connect(&mut self) -> Result<&mut TcpStream, DeliveryError> {
        if self.stream.is_none() {
            // Любой сбой на фазе подключения = кадр relay НЕ получил, поэтому
            // повтор безопасен (в отличие от обрыва уже отправленного кадра).
            let stream = socks5_connect(&self.socks, &self.dest).map_err(DeliveryError::Connect)?;
            self.stream = Some(stream);
        }
        Ok(self.stream.as_mut().expect("just connected"))
    }
}
/// Consumes the BND.ADDR+PORT suffix of a successful SOCKS5 CONNECT reply.
/// Unknown ATYP and truncated suffixes are errors; returning a partially consumed
/// stream to the frame parser is forbidden.
fn consume_socks5_bnd<R: Read>(reader: &mut R, atyp: u8) -> std::io::Result<()> {
    match atyp {
        0x01 => {
            let mut skip = [0u8; 6]; // IPv4 + port
            reader.read_exact(&mut skip)
        }
        0x04 => {
            let mut skip = [0u8; 18]; // IPv6 + port
            reader.read_exact(&mut skip)
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len)?;
            let mut skip = vec![0u8; len[0] as usize + 2]; // domain + port
            reader.read_exact(&mut skip)
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SOCKS5 unsupported BND.ADDR type {other:#04x}"),
        )),
    }
}

/// SOCKS5 CONNECT (no auth) к `host:port` через `socks_addr`.
/// Домен передаём целиком: `.onion` обязан резолвиться внутри Tor.
fn socks5_connect(socks_addr: &str, dest: &str) -> Result<TcpStream, min_net::NetError> {
    eprintln!("[min-socks] connect: socks={socks_addr} dest={dest}");
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| min_net::NetError::Transport("dest без порта".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| min_net::NetError::Transport("bad port".into()))?;
    if host.len() > 255 || host.is_empty() {
        return Err(min_net::NetError::Transport("bad host".into()));
    }

    let mut s = TcpStream::connect(socks_addr).map_err(|e| {
        eprintln!("[min-socks] tcp connect {socks_addr} failed: {e}");
        min_net::NetError::Transport(e.to_string())
    })?;
    s.set_read_timeout(Some(CONNECT_TIMEOUT)).ok();
    s.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();
    s.set_nodelay(true).ok();

    // SOCKS5-клиент: `05 00` (version, no-auth), затем ошибка/результат.
    let _ = s
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| min_net::NetError::Transport(e.to_string()))?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).map_err(|e| {
        eprintln!("[min-socks] greeting read error: {e}");
        min_net::NetError::Transport(e.to_string())
    })?;
    if greet != [0x05, 0x00] {
        return Err(min_net::NetError::Transport(format!(
            "SOCKS5 greeting: {greet:?}"
        )));
    }

    // CONNECT с доменным адресом (ATYP=3).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)
        .map_err(|e| min_net::NetError::Transport(e.to_string()))?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .map_err(|e| min_net::NetError::Transport(e.to_string()))?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(min_net::NetError::Transport(format!(
            "SOCKS5 CONNECT refused: rep={:#04x}",
            head[1]
        )));
    }
    consume_socks5_bnd(&mut s, head[3])
        .map_err(|e| min_net::NetError::Transport(format!("SOCKS5 CONNECT BND read error: {e}")))?;

    s.set_read_timeout(Some(IO_TIMEOUT)).ok();
    s.set_write_timeout(Some(IO_TIMEOUT)).ok();
    Ok(s)
}

impl FrameExchange for SocksLink {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DeliveryError> {
        // Ошибка обрывает поток (перезапуск relay, смена onion circuit). Сбрасываем
        // его, чтобы следующая операция переподключилась вместо бесконечного
        // write/read на мёртвом TCP. Запрос НЕ повторяем здесь: enqueue не идемпотентен.
        let idempotent = min_protocol::frame_api::FrameRequest::from_wire(request)
            .map(|r| r.is_idempotent())
            .unwrap_or(false);
        let result = (|| {
            let stream = self.connect()?;
            let padded = min_net::pad_payload(request, &mut OsRng).map_err(DeliveryError::Net)?;
            write_frame(stream, &padded).map_err(DeliveryError::Net)?;
            // EOF до первого байта ответа: поток закрылся, пока кадр уходил.
            // Для идемпотентных операций (Register/Pull/Ack) это равнозначно
            // «соединения не было» — повтор безопасен, и он реально спасает от
            // «relay closed» на живом Tor. Для Enqueue повтор рисковал бы
            // дублем в чужой очереди, поэтому там остаётся Connect только на
            // невозможности УСТАНОВИТЬ соединение (см. MIN-RED-017).
            let resp = read_frame(stream).map_err(DeliveryError::Net)?;
            let Some(resp) = resp else {
                return Err(if idempotent {
                    DeliveryError::Connect(min_net::NetError::Transport(
                        "relay closed before any response byte".into(),
                    ))
                } else {
                    DeliveryError::Net(min_net::NetError::Transport("relay closed".into()))
                });
            };
            if resp.len() > MAX_FRAME {
                return Err(DeliveryError::Net(min_net::NetError::PayloadTooLarge));
            }
            unpad_payload(&resp).map_err(DeliveryError::Net)
        })();
        if result.is_err() {
            self.stream = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::consume_socks5_bnd;
    use std::io::Cursor;

    #[test]
    fn socks_bnd_ipv4_ipv6_domain_are_consumed_exactly() {
        let mut v4 = Cursor::new([0u8; 6]);
        consume_socks5_bnd(&mut v4, 0x01).unwrap();
        assert_eq!(v4.position(), 6);

        let mut v6 = Cursor::new([0u8; 18]);
        consume_socks5_bnd(&mut v6, 0x04).unwrap();
        assert_eq!(v6.position(), 18);

        let mut domain = Cursor::new([3, b'a', b'b', b'c', 0, 1]);
        consume_socks5_bnd(&mut domain, 0x03).unwrap();
        assert_eq!(domain.position(), 6);
    }

    #[test]
    fn socks_bnd_truncation_and_unknown_atyp_fail_closed() {
        for (bytes, atyp) in [
            (vec![0u8; 5], 0x01),
            (vec![0u8; 17], 0x04),
            (vec![3, b'a', 0, 1], 0x03),
            (vec![0u8; 6], 0x02),
            (vec![0u8; 6], 0xFF),
        ] {
            let mut cursor = Cursor::new(bytes);
            assert!(consume_socks5_bnd(&mut cursor, atyp).is_err());
        }
    }
}
