//! Frame API relay — канонический CBOR-протокол запросов/ответов relay,
//! переносимый фреймами §7 (`u32be(len) || payload`). Это единственный
//! прод-путь; REST-эндпоинты ТЗ §12.3 остаются тестовой обёрткой.
//!
//! Строгий парсинг (PROTOCOL §0): ровно ожидаемый набор ключей в порядке
//! возрастания, строго типы полей, иначе `Malformed` — без «угадывания».

use crate::{canonical_map, expect_u64, map_get, ProtocolError, ProtocolResult};
use ciborium::value::Value;
use min_wire::{canonical_decode_strict, canonical_encode, WireResult};

/// Максимальный размер envelope в кадре (PROTOCOL §3).
const MAX_ENVELOPE: usize = 256 * 1024;
/// Queue cap (PROTOCOL §6): не более 200 позиций в ack-массиве.
const MAX_ACK_IDS: usize = 200;
/// pull_token (32 байта).
const TOKEN_LEN: usize = 32;

/// Тип элемента очереди relay (ACK в очередь не попадает).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum QueueItemType {
    Request = 1,
    Message = 2,
    Control = 3,
}

impl TryFrom<u64> for QueueItemType {
    type Error = ProtocolError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(QueueItemType::Request),
            2 => Ok(QueueItemType::Message),
            3 => Ok(QueueItemType::Control),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Запрос клиента к relay (одна операция на кадр).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameRequest {
    /// Заявить mailbox (claim-once). Ответ: epoch + pull_token.
    Register { mailbox_id: String },
    /// Frame API v2 требует sender mailbox/token для Enqueue.
    Enqueue {
        sender_mailbox: String,
        sender_token: [u8; TOKEN_LEN],
        target_mailbox: String,
        envelope: Vec<u8>,
        item_type: QueueItemType,
    },
    /// Забрать свою очередь (нужен pull_token).
    Pull {
        mailbox_id: String,
        token: [u8; TOKEN_LEN],
    },
    /// Подтвердить обработку позиций (после ack relay их удаляет).
    Ack {
        mailbox_id: String,
        token: [u8; TOKEN_LEN],
        item_ids: Vec<String>,
    },
}

fn expect_tstr(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Строгий чек: ключи map — целые, строго возрастающие (без дубликатов).
fn ascending_keys(root: &Value) -> Option<Vec<u64>> {
    let pairs = match root {
        Value::Map(p) => p,
        _ => return None,
    };
    let keys: Vec<u64> = pairs
        .iter()
        .map(|(k, _)| expect_u64(k))
        .collect::<Option<Vec<_>>>()?;
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return None;
    }
    Some(keys)
}

fn token_bytes(v: &Value) -> ProtocolResult<[u8; TOKEN_LEN]> {
    match v {
        Value::Bytes(b) if b.len() == TOKEN_LEN => {
            let mut t = [0u8; TOKEN_LEN];
            t.copy_from_slice(b);
            Ok(t)
        }
        _ => Err(ProtocolError::Malformed),
    }
}

impl FrameRequest {
    /// Идемпотентна ли операция: безопасно ли повторить её после обрыва.
    ///
    /// `Register`/`Pull`/`Ack` — да: claim-once делает повторный Register
    /// идемпотентным по построению, Pull ничего не меняет, Ack лишь убирает
    /// уже обработанное. `Enqueue` — **нет**: он не имеет client-side
    /// request id, поэтому слепой повтор продублировал бы сообщение в чужой
    /// очереди. Именно поэтому для Enqueue обрыв остаётся fail-closed.
    pub fn is_idempotent(&self) -> bool {
        !matches!(self, FrameRequest::Enqueue { .. })
    }

    /// Ожидаемые ключи map для операции (по возрастанию).
    fn expected_keys(&self) -> Vec<u64> {
        match self {
            FrameRequest::Register { .. } => vec![1, 2],
            FrameRequest::Enqueue { .. } => vec![1, 2, 3, 4, 5, 6],
            FrameRequest::Pull { .. } => vec![1, 2, 3],
            FrameRequest::Ack { .. } => vec![1, 2, 3, 4],
        }
    }

    fn op_code(&self) -> u64 {
        match self {
            FrameRequest::Register { .. } => 1,
            FrameRequest::Enqueue { .. } => 2,
            FrameRequest::Pull { .. } => 3,
            FrameRequest::Ack { .. } => 4,
        }
    }

    fn to_value(&self) -> Value {
        let op = Value::Integer(self.op_code().into());
        match self {
            FrameRequest::Register { mailbox_id } => {
                canonical_map(&[(1, op), (2, Value::Text(mailbox_id.clone()))])
            }
            FrameRequest::Enqueue {
                sender_mailbox,
                sender_token,
                target_mailbox,
                envelope,
                item_type,
            } => canonical_map(&[
                (1, op),
                (2, Value::Text(sender_mailbox.clone())),
                (3, Value::Bytes(sender_token.to_vec())),
                (4, Value::Text(target_mailbox.clone())),
                (5, Value::Bytes(envelope.clone())),
                (6, Value::Integer((*item_type as u64).into())),
            ]),
            FrameRequest::Pull { mailbox_id, token } => canonical_map(&[
                (1, op),
                (2, Value::Text(mailbox_id.clone())),
                (3, Value::Bytes(token.to_vec())),
            ]),
            FrameRequest::Ack {
                mailbox_id,
                token,
                item_ids,
            } => canonical_map(&[
                (1, op),
                (2, Value::Text(mailbox_id.clone())),
                (3, Value::Bytes(token.to_vec())),
                (
                    4,
                    Value::Array(item_ids.iter().map(|id| Value::Text(id.clone())).collect()),
                ),
            ]),
        }
    }

    /// Канонические wire-байты запроса.
    pub fn to_wire(&self) -> WireResult<Vec<u8>> {
        canonical_encode(&self.to_value())
    }

    /// Строгий парс: ровно ожидаемый набор ключей для операции, типы полей
    /// по спецификации, порядок ключей — строго возрастающий.
    pub fn from_wire(bytes: &[u8]) -> ProtocolResult<Self> {
        let root = canonical_decode_strict::<Value>(bytes).map_err(|_| ProtocolError::Malformed)?;
        let keys = ascending_keys(&root).ok_or(ProtocolError::Malformed)?;
        let op = expect_u64(map_get(&root, 1).ok_or(ProtocolError::Malformed)?)
            .ok_or(ProtocolError::Malformed)?;

        let req = match op {
            1 => {
                if keys != vec![1, 2] {
                    return Err(ProtocolError::Malformed);
                }
                let mailbox_id = expect_tstr(map_get(&root, 2).ok_or(ProtocolError::Malformed)?)
                    .ok_or(ProtocolError::Malformed)?;
                FrameRequest::Register { mailbox_id }
            }
            2 => {
                if keys != vec![1, 2, 3, 4, 5, 6] {
                    return Err(ProtocolError::Malformed);
                }
                let sender_mailbox =
                    expect_tstr(map_get(&root, 2).ok_or(ProtocolError::Malformed)?)
                        .ok_or(ProtocolError::Malformed)?;
                let sender_token = token_bytes(map_get(&root, 3).ok_or(ProtocolError::Malformed)?)?;
                let target_mailbox =
                    expect_tstr(map_get(&root, 4).ok_or(ProtocolError::Malformed)?)
                        .ok_or(ProtocolError::Malformed)?;
                let envelope = match map_get(&root, 5).ok_or(ProtocolError::Malformed)? {
                    Value::Bytes(b) if !b.is_empty() && b.len() <= MAX_ENVELOPE => b.clone(),
                    _ => return Err(ProtocolError::Malformed),
                };
                let item_type = QueueItemType::try_from(
                    expect_u64(map_get(&root, 6).ok_or(ProtocolError::Malformed)?)
                        .ok_or(ProtocolError::Malformed)?,
                )?;
                FrameRequest::Enqueue {
                    sender_mailbox,
                    sender_token,
                    target_mailbox,
                    envelope,
                    item_type,
                }
            }
            3 => {
                if keys != vec![1, 2, 3] {
                    return Err(ProtocolError::Malformed);
                }
                let mailbox_id = expect_tstr(map_get(&root, 2).ok_or(ProtocolError::Malformed)?)
                    .ok_or(ProtocolError::Malformed)?;
                let token = token_bytes(map_get(&root, 3).ok_or(ProtocolError::Malformed)?)?;
                FrameRequest::Pull { mailbox_id, token }
            }
            4 => {
                if keys != vec![1, 2, 3, 4] {
                    return Err(ProtocolError::Malformed);
                }
                let mailbox_id = expect_tstr(map_get(&root, 2).ok_or(ProtocolError::Malformed)?)
                    .ok_or(ProtocolError::Malformed)?;
                let token = token_bytes(map_get(&root, 3).ok_or(ProtocolError::Malformed)?)?;
                let ids = match map_get(&root, 4).ok_or(ProtocolError::Malformed)? {
                    Value::Array(items) if items.len() <= MAX_ACK_IDS => items
                        .iter()
                        .map(|v| expect_tstr(v).ok_or(ProtocolError::Malformed))
                        .collect::<ProtocolResult<Vec<_>>>()?,
                    _ => return Err(ProtocolError::Malformed),
                };
                FrameRequest::Ack {
                    mailbox_id,
                    token,
                    item_ids: ids,
                }
            }
            _ => return Err(ProtocolError::Malformed),
        };

        debug_assert_eq!(keys, req.expected_keys());
        Ok(req)
    }
}

/// Код ошибки relay (кадр-ответ не раскрывает деталей сверх кода).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FrameError {
    NotFound = 1,
    Forbidden = 2,
    Conflict = 3,
    BadRequest = 4,
    RateLimited = 5,
    Internal = 6,
}

impl TryFrom<u64> for FrameError {
    type Error = ProtocolError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(FrameError::NotFound),
            2 => Ok(FrameError::Forbidden),
            3 => Ok(FrameError::Conflict),
            4 => Ok(FrameError::BadRequest),
            5 => Ok(FrameError::RateLimited),
            6 => Ok(FrameError::Internal),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Позиция очереди в ответе Pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItemDto {
    pub item_id: String,
    pub envelope: Vec<u8>,
    pub item_type: QueueItemType,
    pub arrived_at: u64,
    pub expires_at: u64,
}

/// Ответ relay на кадр-запрос.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameResponse {
    /// ok(Register): epoch + pull_token (32 байта).
    Register {
        epoch: u64,
        pull_token: [u8; TOKEN_LEN],
    },
    /// ok(Enqueue): item_id + expires_at.
    Enqueue { item_id: String, expires_at: u64 },
    /// ok(Pull): очередь (batch).
    Pull { items: Vec<QueueItemDto> },
    /// ok(Ack): сколько позиций подтверждено.
    Ack { acked: u64 },
    /// err: код ошибки.
    Error { code: FrameError },
}

fn item_to_value(it: &QueueItemDto) -> Value {
    canonical_map(&[
        (1, Value::Text(it.item_id.clone())),
        (2, Value::Bytes(it.envelope.clone())),
        (3, Value::Integer((it.item_type as u64).into())),
        (4, Value::Integer(it.arrived_at.into())),
        (5, Value::Integer(it.expires_at.into())),
    ])
}

impl FrameResponse {
    fn to_value(&self) -> Value {
        match self {
            FrameResponse::Register { epoch, pull_token } => canonical_map(&[
                (1, Value::Integer(1.into())),
                (
                    2,
                    canonical_map(&[
                        (1, Value::Integer((*epoch).into())),
                        (2, Value::Bytes(pull_token.to_vec())),
                    ]),
                ),
            ]),
            FrameResponse::Enqueue {
                item_id,
                expires_at,
            } => canonical_map(&[
                (1, Value::Integer(1.into())),
                (
                    2,
                    canonical_map(&[
                        (1, Value::Text(item_id.clone())),
                        (2, Value::Integer((*expires_at).into())),
                    ]),
                ),
            ]),
            FrameResponse::Pull { items } => canonical_map(&[
                (1, Value::Integer(1.into())),
                (
                    2,
                    canonical_map(&[(1, Value::Array(items.iter().map(item_to_value).collect()))]),
                ),
            ]),
            FrameResponse::Ack { acked } => canonical_map(&[
                (1, Value::Integer(1.into())),
                (2, canonical_map(&[(1, Value::Integer((*acked).into()))])),
            ]),
            FrameResponse::Error { code } => canonical_map(&[
                (1, Value::Integer(2.into())),
                (2, Value::Integer((*code as u64).into())),
            ]),
        }
    }

    /// Канонические wire-байты ответа.
    pub fn to_wire(&self) -> WireResult<Vec<u8>> {
        canonical_encode(&self.to_value())
    }

    /// Строгий парс ответа.
    pub fn from_wire(bytes: &[u8]) -> ProtocolResult<Self> {
        let root = canonical_decode_strict::<Value>(bytes).map_err(|_| ProtocolError::Malformed)?;
        let keys = ascending_keys(&root).ok_or(ProtocolError::Malformed)?;
        if keys != vec![1, 2] {
            return Err(ProtocolError::Malformed);
        }
        let status = expect_u64(map_get(&root, 1).ok_or(ProtocolError::Malformed)?)
            .ok_or(ProtocolError::Malformed)?;

        match status {
            1 => {
                let data = map_get(&root, 2).ok_or(ProtocolError::Malformed)?;
                let dkeys = ascending_keys(data).ok_or(ProtocolError::Malformed)?;
                if dkeys == vec![1, 2] {
                    // Register | Enqueue — различаем типом первого поля.
                    let first = map_get(data, 1).ok_or(ProtocolError::Malformed)?;
                    match first {
                        Value::Integer(_) => {
                            let epoch = expect_u64(first).ok_or(ProtocolError::Malformed)?;
                            let token =
                                token_bytes(map_get(data, 2).ok_or(ProtocolError::Malformed)?)?;
                            Ok(FrameResponse::Register {
                                epoch,
                                pull_token: token,
                            })
                        }
                        Value::Text(_) => {
                            let item_id = expect_tstr(first).ok_or(ProtocolError::Malformed)?;
                            let expires_at =
                                expect_u64(map_get(data, 2).ok_or(ProtocolError::Malformed)?)
                                    .ok_or(ProtocolError::Malformed)?;
                            Ok(FrameResponse::Enqueue {
                                item_id,
                                expires_at,
                            })
                        }
                        _ => Err(ProtocolError::Malformed),
                    }
                } else if dkeys == vec![1] {
                    // Ack | Pull — различаем типом поля 1.
                    let first = map_get(data, 1).ok_or(ProtocolError::Malformed)?;
                    match first {
                        Value::Integer(_) => Ok(FrameResponse::Ack {
                            acked: expect_u64(first).ok_or(ProtocolError::Malformed)?,
                        }),
                        Value::Array(items) => {
                            let parsed = items
                                .iter()
                                .map(item_from_value)
                                .collect::<ProtocolResult<Vec<_>>>()?;
                            Ok(FrameResponse::Pull { items: parsed })
                        }
                        _ => Err(ProtocolError::Malformed),
                    }
                } else {
                    Err(ProtocolError::Malformed)
                }
            }
            2 => {
                let code = FrameError::try_from(
                    expect_u64(map_get(&root, 2).ok_or(ProtocolError::Malformed)?)
                        .ok_or(ProtocolError::Malformed)?,
                )?;
                Ok(FrameResponse::Error { code })
            }
            _ => Err(ProtocolError::Malformed),
        }
    }
}

fn item_from_value(v: &Value) -> ProtocolResult<QueueItemDto> {
    let keys = ascending_keys(v).ok_or(ProtocolError::Malformed)?;
    if keys != vec![1, 2, 3, 4, 5] {
        return Err(ProtocolError::Malformed);
    }
    let item_id = expect_tstr(map_get(v, 1).ok_or(ProtocolError::Malformed)?)
        .ok_or(ProtocolError::Malformed)?;
    let envelope = match map_get(v, 2).ok_or(ProtocolError::Malformed)? {
        Value::Bytes(b) if !b.is_empty() && b.len() <= MAX_ENVELOPE => b.clone(),
        _ => return Err(ProtocolError::Malformed),
    };
    let item_type = QueueItemType::try_from(
        expect_u64(map_get(v, 3).ok_or(ProtocolError::Malformed)?)
            .ok_or(ProtocolError::Malformed)?,
    )?;
    let arrived_at = expect_u64(map_get(v, 4).ok_or(ProtocolError::Malformed)?)
        .ok_or(ProtocolError::Malformed)?;
    let expires_at = expect_u64(map_get(v, 5).ok_or(ProtocolError::Malformed)?)
        .ok_or(ProtocolError::Malformed)?;
    Ok(QueueItemDto {
        item_id,
        envelope,
        item_type,
        arrived_at,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_roundtrip() {
        let req = FrameRequest::Register {
            mailbox_id: "abc".into(),
        };
        let bytes = req.to_wire().unwrap();
        assert_eq!(FrameRequest::from_wire(&bytes).unwrap(), req);
    }

    #[test]
    fn enqueue_roundtrip() {
        let req = FrameRequest::Enqueue {
            sender_mailbox: "sender".into(),
            sender_token: [3u8; TOKEN_LEN],
            target_mailbox: "mb".into(),
            envelope: vec![7u8; 300],
            item_type: QueueItemType::Message,
        };
        let bytes = req.to_wire().unwrap();
        assert_eq!(FrameRequest::from_wire(&bytes).unwrap(), req);
    }

    #[test]
    fn pull_roundtrip() {
        let req = FrameRequest::Pull {
            mailbox_id: "mb".into(),
            token: [9u8; TOKEN_LEN],
        };
        let bytes = req.to_wire().unwrap();
        assert_eq!(FrameRequest::from_wire(&bytes).unwrap(), req);
    }

    #[test]
    fn old_four_field_enqueue_is_rejected_by_v2_parser() {
        let legacy = canonical_map(&[
            (1, Value::Integer(2.into())),
            (2, Value::Text("target".into())),
            (3, Value::Bytes(vec![7u8; 16])),
            (4, Value::Integer(2.into())),
        ]);
        let bytes = canonical_encode(&legacy).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn ack_roundtrip() {
        let req = FrameRequest::Ack {
            mailbox_id: "mb".into(),
            token: [1u8; TOKEN_LEN],
            item_ids: vec!["id1".into(), "id2".into()],
        };
        let bytes = req.to_wire().unwrap();
        assert_eq!(FrameRequest::from_wire(&bytes).unwrap(), req);
    }

    #[test]
    fn unknown_op_rejected() {
        let v = canonical_map(&[(1, Value::Integer(99.into())), (2, Value::Text("x".into()))]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn extra_key_rejected() {
        let v = canonical_map(&[
            (1, Value::Integer(1.into())),
            (2, Value::Text("mb".into())),
            (3, Value::Text("extra".into())),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn out_of_order_keys_rejected() {
        let v = Value::Map(vec![
            (Value::Integer(2.into()), Value::Text("mb".into())),
            (Value::Integer(1.into()), Value::Integer(1.into())),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn duplicate_keys_rejected() {
        let v = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Text("mb".into())),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn wrong_token_length_rejected() {
        let v = canonical_map(&[
            (1, Value::Integer(3.into())),
            (2, Value::Text("mb".into())),
            (3, Value::Bytes(vec![0u8; 16])), // должно быть 32
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn empty_envelope_rejected() {
        let v = canonical_map(&[
            (1, Value::Integer(2.into())),
            (2, Value::Text("mb".into())),
            (3, Value::Bytes(vec![])),
            (4, Value::Integer(2.into())),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn oversize_ack_array_rejected() {
        let ids: Vec<Value> = (0..=MAX_ACK_IDS)
            .map(|i| Value::Text(format!("id{i}")))
            .collect();
        let v = canonical_map(&[
            (1, Value::Integer(4.into())),
            (2, Value::Text("mb".into())),
            (3, Value::Bytes(vec![0u8; TOKEN_LEN])),
            (4, Value::Array(ids)),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameRequest::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn response_roundtrips() {
        let cases = vec![
            FrameResponse::Register {
                epoch: 3,
                pull_token: [5u8; TOKEN_LEN],
            },
            FrameResponse::Enqueue {
                item_id: "mb-aa".into(),
                expires_at: 999,
            },
            FrameResponse::Pull {
                items: vec![QueueItemDto {
                    item_id: "mb-aa".into(),
                    envelope: vec![1, 2, 3],
                    item_type: QueueItemType::Request,
                    arrived_at: 10,
                    expires_at: 20,
                }],
            },
            FrameResponse::Ack { acked: 2 },
            FrameResponse::Error {
                code: FrameError::Forbidden,
            },
        ];
        for resp in cases {
            let bytes = resp.to_wire().unwrap();
            assert_eq!(FrameResponse::from_wire(&bytes).unwrap(), resp);
        }
    }

    #[test]
    fn response_unknown_error_code_rejected() {
        let v = canonical_map(&[
            (1, Value::Integer(2.into())),
            (2, Value::Integer(42.into())),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameResponse::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn response_extra_key_rejected() {
        let v = canonical_map(&[
            (1, Value::Integer(2.into())),
            (2, Value::Integer(1.into())),
            (3, Value::Text("x".into())),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameResponse::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn pull_item_wrong_keys_rejected() {
        let item = canonical_map(&[(1, Value::Text("id".into())), (2, Value::Bytes(vec![1u8]))]);
        let v = canonical_map(&[
            (1, Value::Integer(1.into())),
            (2, canonical_map(&[(1, Value::Array(vec![item]))])),
        ]);
        let bytes = canonical_encode(&v).unwrap();
        assert_eq!(
            FrameResponse::from_wire(&bytes),
            Err(ProtocolError::Malformed)
        );
    }
}
