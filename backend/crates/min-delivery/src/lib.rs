//! Клиент доставки (mailbox client) поверх линка `FrameExchange`.
//!
//! Единственный способ говорить с relay: канонический CBOR `FrameRequest`
//! → `FrameResponse` (PROTOCOL §10), паддинг размеров — забота линка
//! (min-net size classes). MIN-RED-011: паддинг скрывает размер только от
//! наблюдателя канала; relay разбирает CBOR и знает длину конверта.
//!
//! Реализации линка:
//! - `tcp_link::TcpLink` — блокирующий TCP (localhost-тесты / dev-харнесс);
//! - `socks_link::SocksLink` — SOCKS5 к локальному Tor (прод-путь iOS:
//!   C Tor + IPtProxy-мосты);
//! - `TorTransport` (min-tor) — in-process Arti transport for desktop/future use;
//!   the current iOS client uses the SOCKS link to in-app C Tor + IPtProxy.

pub mod socks_link;
pub mod tcp_link;

use min_net::NetError;
use min_protocol::frame_api::{
    FrameError, FrameRequest, FrameResponse, QueueItemDto, QueueItemType,
};
use min_protocol::ProtocolError;
use thiserror::Error;

/// pull_token (32 байта).
pub const TOKEN_LEN: usize = 32;

/// Ошибки клиента доставки.
#[derive(Debug, Error)]
pub enum DeliveryError {
    /// Релей ответил err-кадром (единственный «нормальный» бизнес-отказ).
    #[error("relay error: {0:?}")]
    Relay(FrameError),
    #[error("protocol error: {0}")]
    Protocol(ProtocolError),
    #[error("network error: {0}")]
    Net(NetError),
    /// Соединение не установлено, запрос НЕ отправлен. Единственный сетевой
    /// сбой, при котором повтор безопасен: relay ничего не получил, поэтому
    /// дубль enqueue невозможен (в отличие от обрыва уже отправленного).
    #[error("connect failed (not sent): {0}")]
    Connect(NetError),
}

pub type DeliveryResult<T> = Result<T, DeliveryError>;

/// Линк обмена кадрами: raw CBOR запрос → raw CBOR ответ.
///
/// Контракт паддинга: реализация ЛИНКА паддирует обе стороны (клиентский
/// запрос и ответ релея) — `MailboxClient` оперирует только каноническим
/// CBOR и не знает о размерных классах.
pub trait FrameExchange {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DeliveryError>;
}

/// Mailbox-клиент: register / enqueue / pull / ack (PROTOCOL §10).
pub struct MailboxClient<T: FrameExchange> {
    link: T,
    sender_mailbox: Option<String>,
    sender_token: Option<[u8; TOKEN_LEN]>,
}

impl<T: FrameExchange> MailboxClient<T> {
    pub fn new(link: T) -> Self {
        Self {
            link,
            sender_mailbox: None,
            sender_token: None,
        }
    }

    /// Восстанавливает sender credentials из локально сохранённого токена.
    /// Нужен после рестарта relay: повторный Register не отправляется, чтобы
    /// публичный mailbox нельзя было hijack-нуть, но Enqueue требует auth.
    pub fn set_sender_credentials(&mut self, mailbox_id: &str, token: [u8; TOKEN_LEN]) {
        self.sender_mailbox = Some(mailbox_id.to_string());
        self.sender_token = Some(token);
    }

    /// Один кадр-запрос → разбор кадра-ответа. err-кадр → `DeliveryError::Relay`.
    fn roundtrip(&mut self, req: FrameRequest) -> DeliveryResult<FrameResponse> {
        let wire = req
            .to_wire()
            .map_err(|e| DeliveryError::Protocol(e.into()))?;
        let resp_wire = self.link.exchange(&wire)?;
        match FrameResponse::from_wire(&resp_wire) {
            Ok(FrameResponse::Error { code }) => Err(DeliveryError::Relay(code)),
            Ok(resp) => Ok(resp),
            Err(e) => Err(DeliveryError::Protocol(e)),
        }
    }

    /// Ожидает Register-ответ, иное → `Protocol`.
    pub fn register(&mut self, mailbox_id: &str) -> DeliveryResult<(u64, [u8; TOKEN_LEN])> {
        match self.roundtrip(FrameRequest::Register {
            mailbox_id: mailbox_id.into(),
        })? {
            FrameResponse::Register { epoch, pull_token } => {
                self.sender_mailbox = Some(mailbox_id.to_string());
                self.sender_token = Some(pull_token);
                Ok((epoch, pull_token))
            }
            _ => Err(DeliveryError::Protocol(ProtocolError::Malformed)),
        }
    }

    /// Ожидает Enqueue-ответ.
    pub fn enqueue(
        &mut self,
        target_mailbox: &str,
        envelope: &[u8],
        item_type: QueueItemType,
    ) -> DeliveryResult<(String, u64)> {
        let (Some(sender_mailbox), Some(sender_token)) =
            (self.sender_mailbox.as_ref(), self.sender_token)
        else {
            return Err(DeliveryError::Protocol(ProtocolError::Malformed));
        };
        match self.roundtrip(FrameRequest::Enqueue {
            sender_mailbox: sender_mailbox.clone(),
            sender_token,
            target_mailbox: target_mailbox.into(),
            envelope: envelope.to_vec(),
            item_type,
        })? {
            FrameResponse::Enqueue {
                item_id,
                expires_at,
            } => Ok((item_id, expires_at)),
            _ => Err(DeliveryError::Protocol(ProtocolError::Malformed)),
        }
    }

    /// Ожидает Pull-ответ (batch очереди).
    pub fn pull(
        &mut self,
        mailbox_id: &str,
        token: &[u8; TOKEN_LEN],
    ) -> DeliveryResult<Vec<QueueItemDto>> {
        match self.roundtrip(FrameRequest::Pull {
            mailbox_id: mailbox_id.into(),
            token: *token,
        })? {
            FrameResponse::Pull { items } => Ok(items),
            _ => Err(DeliveryError::Protocol(ProtocolError::Malformed)),
        }
    }

    /// Ожидает Ack-ответ (сколько позиций подтверждено).
    pub fn ack(
        &mut self,
        mailbox_id: &str,
        token: &[u8; TOKEN_LEN],
        item_ids: &[String],
    ) -> DeliveryResult<u64> {
        match self.roundtrip(FrameRequest::Ack {
            mailbox_id: mailbox_id.into(),
            token: *token,
            item_ids: item_ids.to_vec(),
        })? {
            FrameResponse::Ack { acked } => Ok(acked),
            _ => Err(DeliveryError::Protocol(ProtocolError::Malformed)),
        }
    }
}
