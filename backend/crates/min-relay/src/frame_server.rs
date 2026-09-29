//! Frame server relay (PROTOCOL §7): сырой TCP `u32be(len) || payload`
//! с каноническим CBOR внутри (см. min_protocol::frame_api). Это прод-путь
//! поверх Tor; REST (ТЗ §12.3) остаётся тестовой обёрткой.
//!
//! Одна операция на соединение-кадр: запрос → ответ → (клиент может послать
//! следующий кадр в том же соединении; EOF закрывает).

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use min_protocol::frame_api::{
    FrameError, FrameRequest, FrameResponse, QueueItemDto, QueueItemType,
};

use crate::antispam::op_cost;
use crate::logfmt;
use crate::store::{
    ItemType, QueueItem, SharedStore, MESSAGE_QUEUE_CAP, MESSAGE_TTL_SEC, REQUEST_QUEUE_CAP,
    REQUEST_TTL_SEC,
};

/// Максимальный размер кадра (PROTOCOL §7).
const MAX_FRAME: usize = 256 * 1024;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Диспетчер: один кадр-запрос → один кадр-ответ. Чистая функция над store,
/// используется и TCP-сервером, и (позже) REST-адаптером.
///
/// AUDIT MIN-01: перед каждой операцией списывается токен из rate limiter
/// (token bucket per mailbox, antispam.rs). Отказ → err-кадр RateLimited.
///
/// Логирование (beta): обёртка вокруг `dispatch` пишет одну строку на операцию
/// (op / маскированный mailbox / результат) — см. `ReqCtx` и `logfmt`.
pub async fn handle_frame(store: &SharedStore, req: FrameRequest) -> FrameResponse {
    if !valid_mailbox_id(request_mailbox_id(&req))
        || request_sender_mailbox(&req).is_some_and(|id| !valid_mailbox_id(id))
    {
        return FrameResponse::Error {
            code: FrameError::BadRequest,
        };
    }
    let ctx = ReqCtx::of(&req);
    let resp = dispatch(store, req).await;
    ctx.log(&resp);
    resp
}

/// Контекст запроса для логов: без секретов — маски и размеры.
struct ReqCtx {
    op: &'static str,
    /// Маскированный mailbox, к которому относится операция.
    mb: String,
    /// Класс размера envelope: точная длина — метаданные (MIN-RED-014).
    size: &'static str,
    /// Подтип (для enqueue).
    kind: Option<&'static str>,
    /// Сколько item_id запрошено (ack).
    requested: usize,
}

impl ReqCtx {
    fn of(req: &FrameRequest) -> Self {
        match req {
            FrameRequest::Register { mailbox_id } => Self {
                op: "register",
                mb: logfmt::mask(mailbox_id),
                size: "-",
                kind: None,
                requested: 0,
            },
            FrameRequest::Enqueue {
                sender_mailbox,
                target_mailbox: _,
                envelope,
                item_type,
                ..
            } => Self {
                op: "enqueue",
                mb: logfmt::mask(sender_mailbox),
                size: logfmt::size_class(envelope.len()),
                kind: Some(match item_type {
                    QueueItemType::Request => "request",
                    QueueItemType::Message => "message",
                    QueueItemType::Control => "control",
                }),
                requested: 0,
            },
            FrameRequest::Pull { mailbox_id, .. } => Self {
                op: "pull",
                mb: logfmt::mask(mailbox_id),
                size: "-",
                kind: None,
                requested: 0,
            },
            FrameRequest::Ack {
                mailbox_id,
                item_ids,
                ..
            } => Self {
                op: "ack",
                mb: logfmt::mask(mailbox_id),
                size: "-",
                kind: None,
                requested: item_ids.len(),
            },
        }
    }

    /// Одна строка на операцию. Уровень — по смыслу результата:
    /// ok → debug, отказы-сигналы → warn, внутренние ошибки → error.
    fn log(&self, resp: &FrameResponse) {
        let op = self.op;
        let mb = self.mb.as_str();
        match resp {
            FrameResponse::Register { epoch, .. } => {
                // pull_token НИКОГДА не логируем.
                tracing::debug!(op, mb, epoch, "ok: mailbox registered, token issued");
            }
            FrameResponse::Enqueue {
                item_id,
                expires_at,
            } => {
                tracing::debug!(
                    op,
                    mb,
                    item = %logfmt::mask(item_id),
                    kind = self.kind.unwrap_or("?"),
                    size = self.size,
                    expires_at,
                    "ok: message accepted"
                );
            }
            FrameResponse::Pull { items } => {
                let bytes: usize = items.iter().map(|i| i.envelope.len()).sum();
                tracing::debug!(
                    op,
                    mb,
                    count = items.len(),
                    size = logfmt::size_class(bytes),
                    "ok: queue returned"
                );
            }
            FrameResponse::Ack { acked } => {
                tracing::debug!(
                    op,
                    mb,
                    requested = self.requested,
                    acked,
                    "ok: acknowledged"
                );
            }
            FrameResponse::Error { code } => match code {
                FrameError::RateLimited => tracing::warn!(op, mb, "rejected: rate limited"),
                FrameError::Forbidden => {
                    tracing::warn!(op, mb, "rejected: invalid token (bruteforce?)")
                }
                FrameError::BadRequest => tracing::warn!(op, mb, "rejected: invalid request"),
                FrameError::NotFound => tracing::debug!(op, mb, "rejected: mailbox not found"),
                FrameError::Conflict => tracing::debug!(op, mb, "rejected: mailbox already exists"),
                FrameError::Internal => tracing::error!(op, mb, "ERROR: internal"),
            },
        }
    }
}

/// Верхняя граница mailbox_id для rate-limit/storage. Это relay-side
/// resource policy, не wire constraint: CBOR parser принимает прежний tstr,
/// а dispatcher отклоняет oversized key до limiter/state/queue.
const MAX_MAILBOX_ID: usize = 256;

fn valid_mailbox_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_MAILBOX_ID && !id.chars().any(char::is_whitespace)
}

fn request_mailbox_id(req: &FrameRequest) -> &str {
    match req {
        FrameRequest::Register { mailbox_id }
        | FrameRequest::Pull { mailbox_id, .. }
        | FrameRequest::Ack { mailbox_id, .. } => mailbox_id,
        FrameRequest::Enqueue { target_mailbox, .. } => target_mailbox,
    }
}

fn request_sender_mailbox(req: &FrameRequest) -> Option<&str> {
    match req {
        FrameRequest::Enqueue { sender_mailbox, .. } => Some(sender_mailbox),
        _ => None,
    }
}

/// Диспетчер операций (без логирования — логирует `handle_frame`).
async fn dispatch(store: &SharedStore, req: FrameRequest) -> FrameResponse {
    if !valid_mailbox_id(request_mailbox_id(&req))
        || request_sender_mailbox(&req).is_some_and(|id| !valid_mailbox_id(id))
    {
        return FrameResponse::Error {
            code: FrameError::BadRequest,
        };
    }
    // Лимит-гейт: списывает токен ДО любой бизнес-логики (включая проверку
    // токена доступа) — перебор pull_token тоже капится.
    // AUDIT RT-26.4 (F-3): вдобавок к per-mailbox проверяется глобальный
    // bucket — ротация свежих mailbox_id больше не обходит лимиты.
    async fn rate_allowed(store: &SharedStore, key: &str, cost: u32) -> bool {
        let mut s = store.write().await;
        // Порядок важен (как было): при отказе per-mailbox глобальный токен
        // НЕ списывается — иначе честные клиенты платили бы за чужой флуд.
        if !s.check_rate(key, cost) {
            tracing::warn!(
                mb = %logfmt::mask(key),
                cost,
                bucket = "mailbox",
                "rate limit: no tokens (per-mailbox)"
            );
            return false;
        }
        if !s.check_rate_global(cost) {
            tracing::warn!(
                mb = %logfmt::mask(key),
                cost,
                bucket = "global",
                "rate limit: no tokens (global)"
            );
            return false;
        }
        true
    }
    match req {
        FrameRequest::Register { mailbox_id } => {
            if !rate_allowed(store, &mailbox_id, op_cost::REGISTER).await {
                return FrameResponse::Error {
                    code: FrameError::RateLimited,
                };
            }
            let mut s = store.write().await;
            match s.register(mailbox_id.clone()) {
                Ok(token_hex) => {
                    let epoch = s.get(mailbox_id.as_str()).map(|m| m.epoch).unwrap_or(1);
                    match token_bytes(&token_hex) {
                        Some(token) => FrameResponse::Register {
                            epoch,
                            pull_token: token,
                        },
                        None => FrameResponse::Error {
                            code: FrameError::Internal,
                        },
                    }
                }
                Err("mailbox already exists") => FrameResponse::Error {
                    code: FrameError::Conflict,
                },
                Err("invalid mailbox id") => FrameResponse::Error {
                    code: FrameError::BadRequest,
                },
                Err("mailbox capacity reached") => FrameResponse::Error {
                    code: FrameError::RateLimited,
                },
                Err("auth state unavailable") => FrameResponse::Error {
                    code: FrameError::Internal,
                },
                Err(_) => FrameResponse::Error {
                    code: FrameError::Internal,
                },
            }
        }
        FrameRequest::Enqueue {
            sender_mailbox,
            sender_token,
            target_mailbox,
            envelope,
            item_type,
        } => {
            let cost = match item_type {
                QueueItemType::Request => op_cost::ENQUEUE_REQUEST,
                _ => op_cost::ENQUEUE_MESSAGE,
            };
            // Сначала доказательство владения sender mailbox, только потом
            // rate-limit: посторонний не может расходовать bucket жертвы.
            let authorized = {
                let s = store.read().await;
                s.get(&sender_mailbox)
                    .is_some_and(|mb| mb.check_token(&hex::encode(sender_token)))
            };
            if !authorized {
                return FrameResponse::Error {
                    code: FrameError::Forbidden,
                };
            }
            if !rate_allowed(store, &sender_mailbox, cost).await {
                return FrameResponse::Error {
                    code: FrameError::RateLimited,
                };
            }
            let ttl = match item_type {
                QueueItemType::Request => REQUEST_TTL_SEC,
                _ => MESSAGE_TTL_SEC,
            };
            let now = now_secs();
            let suffix = hex::encode(crate::store::random_bytes(16));
            let item_id = format!("{target_mailbox}-{suffix}");
            let store_item = QueueItem {
                item_id: item_id.clone(),
                envelope_hex: hex::encode(&envelope),
                arrived_at: now,
                expires_at: now + ttl,
                item_type: match item_type {
                    QueueItemType::Request => ItemType::Request,
                    QueueItemType::Message => ItemType::Message,
                    QueueItemType::Control => ItemType::Control,
                },
                acked: false,
            };
            let mut s = store.write().await;
            match s.enqueue(&target_mailbox, store_item) {
                Ok(()) => {
                    let queue_len = s.get(&target_mailbox).map(|m| m.queue.len()).unwrap_or(0);
                    tracing::trace!(
                        mb = %logfmt::mask(&target_mailbox),
                        queue_len,
                        "queue depth after enqueue"
                    );
                    FrameResponse::Enqueue {
                        item_id,
                        expires_at: now + ttl,
                    }
                }
                Err("queue full") => {
                    let cap = match item_type {
                        QueueItemType::Request => REQUEST_QUEUE_CAP,
                        _ => MESSAGE_QUEUE_CAP,
                    };
                    tracing::warn!(
                        mb = %logfmt::mask(&target_mailbox),
                        cap,
                        "queue full — message not accepted"
                    );
                    FrameResponse::Error {
                        code: FrameError::RateLimited,
                    }
                }
                Err("mailbox not found") => FrameResponse::Error {
                    code: FrameError::NotFound,
                },
                Err(_) => FrameResponse::Error {
                    code: FrameError::Internal,
                },
            }
        }
        FrameRequest::Pull { mailbox_id, token } => {
            if !rate_allowed(store, &mailbox_id, op_cost::PULL).await {
                return FrameResponse::Error {
                    code: FrameError::RateLimited,
                };
            }
            let mut s = store.write().await;
            let Some(mb) = s.get_mut(&mailbox_id) else {
                return FrameResponse::Error {
                    code: FrameError::NotFound,
                };
            };
            if !mb.check_token(&hex::encode(token)) {
                return FrameResponse::Error {
                    code: FrameError::Forbidden,
                };
            }
            s.prune_expired(now_secs());
            let items = s
                .get(&mailbox_id)
                .map(|mb| {
                    mb.queue
                        .iter()
                        .filter(|q| !q.acked)
                        .map(|q| QueueItemDto {
                            item_id: q.item_id.clone(),
                            envelope: hex::decode(&q.envelope_hex).unwrap_or_default(),
                            item_type: match q.item_type {
                                ItemType::Request => QueueItemType::Request,
                                ItemType::Message => QueueItemType::Message,
                                ItemType::Control => QueueItemType::Control,
                            },
                            arrived_at: q.arrived_at,
                            expires_at: q.expires_at,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            // MIN-RED-014: точные длины конвертов — метаданные (оператор реле
            // видел бы длину каждого сообщения и мог строить профиль активности).
            // В лог идёт только порядковый класс размера.
            tracing::trace!(
                mb = %logfmt::mask(&mailbox_id),
                items = ?items
                    .iter()
                    .map(|i| (logfmt::mask(&i.item_id), logfmt::size_class(i.envelope.len())))
                    .collect::<Vec<_>>(),
                "pull composition (masked ids, size classes)"
            );
            FrameResponse::Pull { items }
        }
        FrameRequest::Ack {
            mailbox_id,
            token,
            item_ids,
        } => {
            if !rate_allowed(store, &mailbox_id, op_cost::ACK).await {
                return FrameResponse::Error {
                    code: FrameError::RateLimited,
                };
            }
            let mut s = store.write().await;
            let Some(mb) = s.get_mut(&mailbox_id) else {
                return FrameResponse::Error {
                    code: FrameError::NotFound,
                };
            };
            if !mb.check_token(&hex::encode(token)) {
                return FrameResponse::Error {
                    code: FrameError::Forbidden,
                };
            }
            let mut acked = 0u64;
            for id in &item_ids {
                if s.ack(&mailbox_id, id) {
                    acked += 1;
                }
            }
            FrameResponse::Ack { acked }
        }
    }
}

fn token_bytes(hex_str: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_str).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut t = [0u8; 32];
    t.copy_from_slice(&raw);
    Some(t)
}

/// Читает один кадр `u32be(len) || payload` (PROTOCOL §7). None = EOF.
async fn read_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds cap",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Пишет кадр `u32be(len) || payload` (PROTOCOL §7).
async fn write_frame(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Живёт, пока соединение открыто: кадр → диспетчер → кадр.
///
/// Линк-слой паддирует обе стороны (min-net). ВАЖНО (MIN-RED-011): padding
/// скрывает длину только от пассивного наблюдателя канала, но НЕ от relay —
/// relay обязан разобрать CBOR-запрос, а `Value::Bytes` несёт явную длину
/// конверта. Прежнее утверждение «relay не видит точных размеров» было неверным.
async fn serve_connection(store: SharedStore, mut stream: tokio::net::TcpStream) {
    loop {
        match read_frame(&mut stream).await {
            Ok(Some(padded)) => {
                let payload = match min_net::unpad_payload(&padded) {
                    Ok(p) => p,
                    Err(_) => {
                        // MIN-RED-014: точная длина — метаданные. Оператор реле
                        // наблюдает канал и по длине построил бы профиль
                        // активности, поэтому только класс размера.
                        tracing::warn!(
                            size = logfmt::size_class(padded.len()),
                            "padding corrupted → BadRequest (connection kept)"
                        );
                        let err = FrameResponse::Error {
                            code: FrameError::BadRequest,
                        }
                        .to_wire()
                        .unwrap_or_default();
                        let padded_err =
                            min_net::pad_payload(&err, &mut rand_core::OsRng).unwrap_or(err);
                        if write_frame(&mut stream, &padded_err).await.is_err() {
                            return;
                        }
                        continue;
                    }
                };
                tracing::trace!(
                    pad = logfmt::size_class(padded.len()),
                    payload = logfmt::size_class(payload.len()),
                    "frame parsed"
                );
                let response = match FrameRequest::from_wire(&payload) {
                    Ok(req) => handle_frame(&store, req).await,
                    // Строгий парсинг: мусор → err-кадр, соединение не рвём
                    // (не даём атакующему дешёвый DoS канала).
                    Err(_) => {
                        // debug, а не warn: мусор в кадре дёшев для атакующего
                        // (иначе он может накрутить лог-файл). Размер — классом
                        // (MIN-RED-014): точное число отражает только мусор,
                        // но огрубление даёт фиксированную ширину поля.
                        tracing::debug!(
                            size = logfmt::size_class(payload.len()),
                            "invalid frame → BadRequest"
                        );
                        FrameResponse::Error {
                            code: FrameError::BadRequest,
                        }
                    }
                };
                let wire = match response.to_wire() {
                    Ok(w) => w,
                    Err(_) => {
                        tracing::error!("cannot encode response — closing connection");
                        return; // не можем закодировать ответ — закрываем
                    }
                };
                let padded = min_net::pad_payload(&wire, &mut rand_core::OsRng).unwrap_or(wire);
                if let Err(e) = write_frame(&mut stream, &padded).await {
                    tracing::debug!(err = %e, "failed to write response — closing");
                    return;
                }
            }
            Ok(None) => {
                tracing::trace!("EOF — client closed connection");
                return; // EOF — штатное закрытие
            }
            Err(e) => {
                tracing::debug!(err = %e, "read error/malformed frame — closing connection");
                return; // кривой кадр/обрыв — закрываем
            }
        }
    }
}

/// TCP-сервер кадров. Слушает `addr` (для Tor это localhost позади onion
/// сервиса, PROTOCOL §7: прод-транспорт — onion).
pub async fn serve_frames(store: SharedStore, addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("MIN relay frame server listening on {addr}");
    loop {
        let (stream, peer) = listener.accept().await?;
        // MIN-RED-014: адрес пира в лог НЕ пишем. За Tor это всегда
        // 127.0.0.1 (адреса клиентов мы не знаем — анонимность транспорта),
        // но если relay когда-либо откроют наружу или в LAN, в лог попали бы
        // реальные IP клиентов. Для диагностики достаточно признака
        // «локальный/не локальный» и самого факта подключения.
        let loopback = peer.ip().is_loopback();
        tracing::debug!(loopback, "new connection");
        let store = Arc::clone(&store);
        tokio::spawn(serve_connection(store, stream));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ItemType, QueueItem, SharedStore, Store, MESSAGE_QUEUE_CAP};
    use min_protocol::frame_api::{FrameRequest, FrameResponse};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn store() -> SharedStore {
        Arc::new(RwLock::new(Store::new()))
    }

    async fn register_token(store: &SharedStore, mailbox: &str) -> [u8; 32] {
        match handle_frame(
            store,
            FrameRequest::Register {
                mailbox_id: mailbox.into(),
            },
        )
        .await
        {
            FrameResponse::Register { pull_token, .. } => pull_token,
            other => panic!("register {mailbox} failed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_enqueue_pull_ack_cycle() {
        let store = store();

        let resp = handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "MB1".into(),
            },
        )
        .await;
        let FrameResponse::Register { epoch, pull_token } = resp else {
            panic!("expected Register, got {resp:?}");
        };
        assert_eq!(epoch, 1);

        let resp = handle_frame(
            &store,
            FrameRequest::Enqueue {
                sender_mailbox: "MB1".into(),
                sender_token: pull_token,
                target_mailbox: "MB1".into(),
                envelope: vec![1u8; 64],
                item_type: QueueItemType::Message,
            },
        )
        .await;
        let FrameResponse::Enqueue { item_id, .. } = resp else {
            panic!("expected Enqueue, got {resp:?}");
        };

        let resp = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "MB1".into(),
                token: pull_token,
            },
        )
        .await;
        let FrameResponse::Pull { items } = resp else {
            panic!("expected Pull, got {resp:?}");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_id, item_id);
        assert_eq!(items[0].envelope, vec![1u8; 64]);

        // Неверный токен → Forbidden.
        let resp = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "MB1".into(),
                token: [0u8; 32],
            },
        )
        .await;
        assert_eq!(
            resp,
            FrameResponse::Error {
                code: FrameError::Forbidden
            }
        );

        // Ack удаляет позицию.
        let resp = handle_frame(
            &store,
            FrameRequest::Ack {
                mailbox_id: "MB1".into(),
                token: pull_token,
                item_ids: vec![item_id],
            },
        )
        .await;
        assert_eq!(resp, FrameResponse::Ack { acked: 1 });

        // Повторный pull — пусто.
        let resp = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "MB1".into(),
                token: pull_token,
            },
        )
        .await;
        assert_eq!(resp, FrameResponse::Pull { items: vec![] });
    }

    #[tokio::test]
    async fn oversized_mailbox_is_rejected_before_limiter_or_store() {
        let store = store();
        let response = handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "m".repeat(257),
            },
        )
        .await;
        assert_eq!(
            response,
            FrameResponse::Error {
                code: FrameError::BadRequest
            }
        );
        assert!(store.read().await.mailboxes.is_empty());
        assert!(store.read().await.limiter.is_empty());
    }

    #[tokio::test]
    async fn pull_unknown_mailbox_is_not_found() {
        let store = store();
        let resp = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "NOPE".into(),
                token: [0u8; 32],
            },
        )
        .await;
        assert_eq!(
            resp,
            FrameResponse::Error {
                code: FrameError::NotFound
            }
        );
    }

    #[tokio::test]
    async fn double_register_is_conflict() {
        let store = store();
        let req = FrameRequest::Register {
            mailbox_id: "MBX".into(),
        };
        let first = handle_frame(&store, req.clone()).await;
        assert!(matches!(first, FrameResponse::Register { .. }));
        let second = handle_frame(&store, req).await;
        assert_eq!(
            second,
            FrameResponse::Error {
                code: FrameError::Conflict
            }
        );
    }

    #[tokio::test]
    async fn enqueue_to_unknown_mailbox_is_not_found() {
        let store = store();
        let sender_token = register_token(&store, "GHOST-SENDER").await;
        let resp = handle_frame(
            &store,
            FrameRequest::Enqueue {
                sender_mailbox: "GHOST-SENDER".into(),
                sender_token,
                target_mailbox: "GHOST".into(),
                envelope: vec![1u8; 16],
                item_type: QueueItemType::Message,
            },
        )
        .await;
        assert_eq!(
            resp,
            FrameResponse::Error {
                code: FrameError::NotFound
            }
        );
    }

    /// RED-006 PoC: unauthenticated sender must not consume the victim's
    /// rate bucket. The old wire had no sender proof at all; v2 rejects it.
    #[tokio::test]
    async fn unauthenticated_enqueue_does_not_consume_victim_rate_bucket() {
        let store = store();
        let victim_token = register_token(&store, "VICTIM-RATE").await;
        let sender_token = register_token(&store, "ATTACKER").await;

        for i in 0..28 {
            let response = handle_frame(
                &store,
                FrameRequest::Enqueue {
                    sender_mailbox: "ATTACKER".into(),
                    sender_token,
                    target_mailbox: "VICTIM-RATE".into(),
                    envelope: vec![i as u8; 32],
                    item_type: QueueItemType::Message,
                },
            )
            .await;
            assert!(matches!(response, FrameResponse::Enqueue { .. }));
        }
        assert_eq!(
            store.read().await.get("VICTIM-RATE").unwrap().queue.len(),
            28
        );
        let blocked = handle_frame(
            &store,
            FrameRequest::Enqueue {
                sender_mailbox: "ATTACKER".into(),
                sender_token,
                target_mailbox: "VICTIM-RATE".into(),
                envelope: vec![0xEE; 32],
                item_type: QueueItemType::Message,
            },
        )
        .await;
        assert_eq!(
            blocked,
            FrameResponse::Error {
                code: FrameError::RateLimited
            }
        );
        let owner = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "VICTIM-RATE".into(),
                token: victim_token,
            },
        )
        .await;
        assert!(matches!(owner, FrameResponse::Pull { .. }));

        // Неверный sender token → Forbidden, target bucket не списывается.
        let unauthorized = handle_frame(
            &store,
            FrameRequest::Enqueue {
                sender_mailbox: "ATTACKER".into(),
                sender_token: [0u8; 32],
                target_mailbox: "VICTIM-RATE".into(),
                envelope: vec![0xAA; 32],
                item_type: QueueItemType::Message,
            },
        )
        .await;
        assert_eq!(
            unauthorized,
            FrameResponse::Error {
                code: FrameError::Forbidden
            }
        );
    }

    /// AUDIT MIN-01: флуд enqueue выше burst → RateLimited, при этом
    /// легитимный burst проходит (не сломан нормальный трафик).
    #[tokio::test]
    async fn rate_limit_blocks_flood() {
        let store = store();
        let sender_token = match handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "FLOOD".into(),
            },
        )
        .await
        {
            FrameResponse::Register { pull_token, .. } => pull_token,
            other => panic!("register FLOOD failed: {other:?}"),
        };

        // burst default = 30, register списал 2: первые 28 enqueue проходят.
        for i in 0..28 {
            let resp = handle_frame(
                &store,
                FrameRequest::Enqueue {
                    sender_mailbox: "FLOOD".into(),
                    sender_token,
                    target_mailbox: "FLOOD".into(),
                    envelope: vec![i as u8; 16],
                    item_type: QueueItemType::Message,
                },
            )
            .await;
            assert!(
                matches!(resp, FrameResponse::Enqueue { .. }),
                "op {i} must pass"
            );
        }
        // Дальше без пополнения — RateLimited.
        let resp = handle_frame(
            &store,
            FrameRequest::Enqueue {
                sender_mailbox: "FLOOD".into(),
                sender_token,
                target_mailbox: "FLOOD".into(),
                envelope: vec![0xEE; 16],
                item_type: QueueItemType::Message,
            },
        )
        .await;
        assert_eq!(
            resp,
            FrameResponse::Error {
                code: FrameError::RateLimited
            }
        );
    }

    /// Полный TCP-цикл через реальный фрейминг §7: Register → Enqueue → Pull,
    /// мусорный кадр → BadRequest-кадр, и соединение продолжает жить.
    #[tokio::test]
    async fn tcp_frame_roundtrip() {
        let store = store();
        // Поднять сервер на эфемерном порту.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = probe.local_addr().unwrap();
        drop(probe);
        tokio::spawn(async move {
            serve_frames(store, &bound.to_string()).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(bound).await.unwrap();

        // Клиент паддирует кадры (линк-слой, как это делает TorTransport).
        async fn send_padded(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
            let padded = min_net::pad_payload(payload, &mut rand_core::OsRng).unwrap();
            write_frame(stream, &padded).await.unwrap();
        }

        // Register.
        let req = FrameRequest::Register {
            mailbox_id: "TCPS".into(),
        };
        send_padded(&mut stream, &req.to_wire().unwrap()).await;
        let wire = read_frame(&mut stream).await.unwrap().unwrap();
        let FrameResponse::Register { pull_token, .. } =
            FrameResponse::from_wire(&min_net::unpad_payload(&wire).unwrap()).unwrap()
        else {
            panic!("expected Register");
        };

        // Enqueue.
        let req = FrameRequest::Enqueue {
            sender_mailbox: "TCPS".into(),
            sender_token: pull_token,
            target_mailbox: "TCPS".into(),
            envelope: vec![9u8; 100],
            item_type: QueueItemType::Message,
        };
        send_padded(&mut stream, &req.to_wire().unwrap()).await;
        let wire = read_frame(&mut stream).await.unwrap().unwrap();
        let resp = FrameResponse::from_wire(&min_net::unpad_payload(&wire).unwrap()).unwrap();
        assert!(matches!(resp, FrameResponse::Enqueue { .. }));

        // Pull.
        let req = FrameRequest::Pull {
            mailbox_id: "TCPS".into(),
            token: pull_token,
        };
        send_padded(&mut stream, &req.to_wire().unwrap()).await;
        let wire = read_frame(&mut stream).await.unwrap().unwrap();
        let FrameResponse::Pull { items } =
            FrameResponse::from_wire(&min_net::unpad_payload(&wire).unwrap()).unwrap()
        else {
            panic!("expected Pull");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].envelope, vec![9u8; 100]);

        // Мусорный (невалидный padding) кадр → BadRequest-кадр, соединение живёт.
        let padded_garbage = {
            let mut g = vec![0u8; 64];
            g[0] = 0xFF; // кривая длина padding-заголовка
            g[1] = 0xFF;
            g
        };
        write_frame(&mut stream, &padded_garbage).await.unwrap();
        let wire = read_frame(&mut stream).await.unwrap().unwrap();
        assert_eq!(
            FrameResponse::from_wire(&min_net::unpad_payload(&wire).unwrap()).unwrap(),
            FrameResponse::Error {
                code: FrameError::BadRequest
            }
        );

        // После мусора продолжается нормальная работа.
        let req = FrameRequest::Pull {
            mailbox_id: "TCPS".into(),
            token: pull_token,
        };
        send_padded(&mut stream, &req.to_wire().unwrap()).await;
        let wire = read_frame(&mut stream).await.unwrap().unwrap();
        let resp = FrameResponse::from_wire(&min_net::unpad_payload(&wire).unwrap()).unwrap();
        assert!(matches!(resp, FrameResponse::Pull { .. }));
    }

    // ========================================================================
    // PHASE 3 (RT-26): relay concurrency + oracle suite
    // ========================================================================

    /// RT-26.3: concurrent register claim-once. 32 потока регистрируют один и
    /// тот же mailbox_id под SharedStore (Arc<RwLock>). Инвариант: ровно один
    /// получает pull_token, остальные — «already exists» (нельзя перехватить
    /// чужой mailbox — PROTOCOL §6).
    #[tokio::test]
    async fn rt26_3_concurrent_register_claim_once() {
        let store = store();
        let mut handles = Vec::new();
        for _ in 0..32 {
            let st = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let mut s = st.write().await;
                s.register("RACE".into())
            }));
        }
        let mut winners = 0usize;
        let mut tokens = Vec::new();
        for h in handles {
            if let Ok(t) = h.await.unwrap() {
                winners += 1;
                tokens.push(t);
            }
        }
        assert_eq!(winners, 1, "exactly one register must win, got {winners}");
        let guard = store.read().await;
        let mb = guard.get("RACE").unwrap();
        assert!(mb.check_token(&tokens[0]), "winner token must be valid");
    }

    /// RT-26.4 (F-3): шардирование rate-limit ротацией свежих mailbox_id.
    /// Атакующий: 400 pull-запросов, каждый со СВОИМ свежим id (per-mailbox
    /// bucket каждый раз полный). До фикса — все проходили. После: глобальный
    /// bucket исчерпывается → RateLimited, до глобального burst'а.
    #[tokio::test]
    async fn rt26_4_rate_limit_cannot_be_sharded_by_fresh_ids() {
        let store = store();
        let mut passed = 0usize;
        let mut limited = 0usize;
        for i in 0..400u32 {
            let resp = handle_frame(
                &store,
                FrameRequest::Pull {
                    mailbox_id: format!("SHARD{i}"),
                    token: [0u8; 32],
                },
            )
            .await;
            match resp {
                FrameResponse::Error {
                    code: FrameError::RateLimited,
                } => limited += 1,
                FrameResponse::Error {
                    code: FrameError::NotFound,
                } => passed += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(limited > 0, "global bucket must stop id-rotation flood");
        assert!(
            passed <= 300,
            "must not exceed global burst, passed={passed}"
        );
    }

    /// RT-26.5: mailbox-existence oracle ограничен. Unknown mailbox → NotFound,
    /// существующий с неверным токеном → Forbidden (коды различаются — это
    /// inherent к store-and-forward; компенсация: probing капится rate
    /// limiter'ом). Тест фиксирует контракт: перебор ограничен burst'ом.
    #[tokio::test]
    async fn rt26_5_existence_probing_is_rate_bounded() {
        let store = store();
        handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "REAL".into(),
            },
        )
        .await;

        // Unknown → NotFound; known + bad token → Forbidden.
        let r1 = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "GHOST".into(),
                token: [0u8; 32],
            },
        )
        .await;
        assert!(matches!(
            r1,
            FrameResponse::Error {
                code: FrameError::NotFound
            }
        ));
        let r2 = handle_frame(
            &store,
            FrameRequest::Pull {
                mailbox_id: "REAL".into(),
                token: [0u8; 32],
            },
        )
        .await;
        assert!(matches!(
            r2,
            FrameResponse::Error {
                code: FrameError::Forbidden
            }
        ));

        // Compensating control: probing лимитирован — после burst'а RateLimited.
        let mut rate_limited_seen = false;
        for i in 0..400 {
            let r = handle_frame(
                &store,
                FrameRequest::Pull {
                    mailbox_id: format!("PROBE{i}"),
                    token: [0u8; 32],
                },
            )
            .await;
            if matches!(
                r,
                FrameResponse::Error {
                    code: FrameError::RateLimited
                }
            ) {
                rate_limited_seen = true;
                break;
            }
        }
        assert!(rate_limited_seen, "existence probing must be rate-bounded");
    }

    /// RT-26.6: online guess budget pull_token. 256-битный токен: полный
    /// перебор невозможен физически; тест фиксирует, что перебор капится rate
    /// limiter'ом (перебор pull тоже списывает токены) и ни одна попытка
    /// не угадывает.
    #[tokio::test]
    async fn rt26_6_token_guess_budget_is_bounded() {
        let store = store();
        handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "MBX".into(),
            },
        )
        .await;

        let mut guessed = false;
        let mut limited = false;
        for i in 0..60 {
            let token = [(i as u8).wrapping_mul(7); 32]; // псевдо-угадывание
            let r = handle_frame(
                &store,
                FrameRequest::Pull {
                    mailbox_id: "MBX".into(),
                    token,
                },
            )
            .await;
            match r {
                FrameResponse::Error {
                    code: FrameError::RateLimited,
                } => limited = true,
                FrameResponse::Error {
                    code: FrameError::Forbidden,
                } => {}
                FrameResponse::Pull { .. } => guessed = true,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(!guessed, "no guess may succeed");
        assert!(
            limited,
            "guessing must hit rate limit (no unlimited oracle)"
        );
    }

    /// RT-26.7: targeted eviction DoS невозможен. Флуд атакующим капится
    /// rate limiter'ом (frame-уровень) и per-mailbox cap'ом (store-уровень);
    /// легитимные письма других mailbox-ов не вытесняются.
    #[tokio::test]
    async fn rt26_7_attacker_flood_cannot_evict_legitimate_mail() {
        let store = store();

        // Жертва: легитимное письмо в очереди.
        let victim_token = match handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "VICTIM".into(),
            },
        )
        .await
        {
            FrameResponse::Register { pull_token, .. } => pull_token,
            other => panic!("register VICTIM failed: {other:?}"),
        };
        handle_frame(
            &store,
            FrameRequest::Enqueue {
                sender_mailbox: "VICTIM".into(),
                sender_token: victim_token,
                target_mailbox: "VICTIM".into(),
                envelope: vec![0xAA; 64],
                item_type: QueueItemType::Message,
            },
        )
        .await;

        // Атакующий заливает СВОЮ очередь: rate limiter (burst 30 − register 2)
        // останавливает флуд раньше cap'а — «queue full» маппится в тот же
        // RateLimited (без oracle).
        let attack_token = match handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "ATK".into(),
            },
        )
        .await
        {
            FrameResponse::Register { pull_token, .. } => pull_token,
            other => panic!("register ATK failed: {other:?}"),
        };
        let mut stopped = false;
        for i in 0..100 {
            let r = handle_frame(
                &store,
                FrameRequest::Enqueue {
                    sender_mailbox: "ATK".into(),
                    sender_token: attack_token,
                    target_mailbox: "ATK".into(),
                    envelope: vec![0x00; 64],
                    item_type: QueueItemType::Message,
                },
            )
            .await;
            if matches!(
                r,
                FrameResponse::Error {
                    code: FrameError::RateLimited
                }
            ) {
                stopped = true;
                break;
            }
            assert!(
                matches!(r, FrameResponse::Enqueue { .. }),
                "i={i} got {r:?}"
            );
        }
        assert!(stopped, "attacker flood must be stopped");
        let atk_len = store.read().await.get("ATK").unwrap().queue.len();
        assert!(
            atk_len < 40,
            "flood must stop well before cap, len={atk_len}"
        );

        // Store-уровень: cap-инвариант независимо от limiter'а — заполнение
        // чистой очереди до 200, 201-е письмо → «queue full» (без eviction).
        {
            let mut s = store.write().await;
            s.register("FILL".into()).unwrap();
            for i in 0..MESSAGE_QUEUE_CAP {
                let item = QueueItem {
                    item_id: format!("fill{i}"),
                    envelope_hex: "00".into(),
                    arrived_at: 1000,
                    expires_at: u64::MAX,
                    item_type: ItemType::Message,
                    acked: false,
                };
                s.enqueue("FILL", item)
                    .unwrap_or_else(|e| panic!("i={i}: {e}"));
            }
            let overflow = QueueItem {
                item_id: "over".into(),
                envelope_hex: "00".into(),
                arrived_at: 1000,
                expires_at: u64::MAX,
                item_type: ItemType::Message,
                acked: false,
            };
            assert_eq!(s.enqueue("FILL", overflow).unwrap_err(), "queue full");
        }
        assert_eq!(
            store.read().await.get("FILL").unwrap().queue.len(),
            MESSAGE_QUEUE_CAP
        );

        // Очередь жертвы не тронута: 1 письмо, eviction не случился.
        let guard = store.read().await;
        let victim = guard.get("VICTIM").unwrap();
        assert_eq!(victim.queue.len(), 1, "victim mail must not be evicted");
        assert_eq!(victim.queue[0].envelope_hex, hex::encode([0xAA; 64]));
    }

    /// RT-26.8: TTL expiry vs claim — ровно один терминальный статус.
    /// Просроченное письмо физически удаляется → после expiry claim невозможен.
    /// (Граница now==expires_at: retain `expires_at > now` — строгое
    /// неравенство, при now=102 письмо уже мертво.)
    #[tokio::test]
    async fn rt26_8_expiry_claim_race_has_single_terminal_state() {
        let store = store();
        handle_frame(
            &store,
            FrameRequest::Register {
                mailbox_id: "TTL".into(),
            },
        )
        .await;
        {
            let mut s = store.write().await;
            s.enqueue(
                "TTL",
                QueueItem {
                    item_id: "edge".into(),
                    envelope_hex: "ff".into(),
                    arrived_at: 100,
                    expires_at: 102,
                    item_type: ItemType::Message,
                    acked: false,
                },
            )
            .unwrap();
        }

        let mut s = store.write().await;
        // now=101 < 102: живо.
        s.prune_expired(101);
        assert!(s
            .get("TTL")
            .unwrap()
            .queue
            .iter()
            .any(|q| q.item_id == "edge"));
        // now=102 == expires_at: expires_at > now — false → мертво.
        s.prune_expired(102);
        assert!(!s
            .get("TTL")
            .unwrap()
            .queue
            .iter()
            .any(|q| q.item_id == "edge"));
        // Claim после expiry невозможен: item физически удалён.
        let claim = s
            .get_mut("TTL")
            .unwrap()
            .queue
            .iter_mut()
            .find(|q| q.item_id == "edge" && !q.acked);
        assert!(claim.is_none(), "expired item must not be claimable");
    }
}
