//! Relay HTTP API (ТЗ §12.3). Только opaque данные, никакого plaintext.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::antispam::op_cost;
use crate::store::{ItemType, QueueItem, SharedStore, MESSAGE_TTL_SEC, REQUEST_TTL_SEC};

pub const PROTOCOL_VERSION: u64 = 1;

/// Заголовок авторизации для pull/ack. Значение — pull_token (hex), выданный при register.
const AUTH_HEADER: &str = "x-min-token";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Извлекает pull_token из заголовка `x-min-token`.
fn extract_token(headers: &HeaderMap) -> Option<&str> {
    headers.get(AUTH_HEADER)?.to_str().ok()
}

// ---- Request/response types ----

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub mailbox_id: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub mailbox_id: String,
    pub epoch: u64,
    /// pull_token — секрет для pull/ack. В iOS хранится в SQLite, зашифрованной
    /// storage key из Keychain; открытый token в UserDefaults/Plist не хранится.
    /// Выдаётся ОДИН раз; при утере — только повторная регистрация (-lossy).
    pub pull_token: String,
}

#[derive(Deserialize)]
pub struct EnqueueRequest {
    pub target_mailbox: String,
    pub envelope_hex: String,
    pub item_type: String, // "request" | "message" | "control"
}

#[derive(Serialize)]
pub struct EnqueueResponse {
    pub item_id: String,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct PullResponse {
    pub items: Vec<PullItem>,
}

#[derive(Serialize)]
pub struct PullItem {
    pub item_id: String,
    pub envelope_hex: String,
    pub item_type: String,
    pub arrived_at: u64,
    pub expires_at: u64,
}

#[derive(Deserialize)]
pub struct AckRequest {
    pub item_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct AckResponse {
    pub acked: usize,
}

#[derive(Serialize)]
pub struct VersionResponse {
    pub protocol_version: u64,
    pub relay: String,
}

/// Ошибка авторизации — 404, чтобы не раскрывать существование mailboxа посторонним.
fn mailbox_not_found() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "mailbox not found".into())
}

/// Ошибка доступа — неправильный/отсутствующий токен.
fn forbidden() -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, "invalid token".into())
}

/// AUDIT MIN-01: rate-limit превышен — 429 (REST-обёртка вокруг фреймов).
fn rate_limited() -> (StatusCode, String) {
    (StatusCode::TOO_MANY_REQUESTS, "rate limited".into())
}

// ---- Handlers ----

pub async fn register(
    State(store): State<SharedStore>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    let mut s = store.write().await;
    // AUDIT MIN-01: rate-limit до бизнес-логики.
    if !s.check_rate(&body.mailbox_id, op_cost::REGISTER) {
        return Err(rate_limited());
    }
    let token = s.register(body.mailbox_id.clone()).map_err(|e| match e {
        "mailbox already exists" => (StatusCode::CONFLICT, e.into()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.into()),
    })?;
    let mb = s.get(&body.mailbox_id).unwrap();
    Ok(Json(RegisterResponse {
        mailbox_id: mb.mailbox_id.clone(),
        epoch: mb.epoch,
        pull_token: token,
    }))
}

pub async fn enqueue(
    State(store): State<SharedStore>,
    Json(body): Json<EnqueueRequest>,
) -> Result<Json<EnqueueResponse>, (StatusCode, String)> {
    let item_type = match body.item_type.as_str() {
        "request" => ItemType::Request,
        "message" => ItemType::Message,
        "control" => ItemType::Control,
        _ => return Err((StatusCode::BAD_REQUEST, "unknown item_type".into())),
    };
    // AUDIT MIN-01: rate-limit по получателю до любой логики.
    let cost = if item_type == ItemType::Request {
        op_cost::ENQUEUE_REQUEST
    } else {
        op_cost::ENQUEUE_MESSAGE
    };
    {
        let mut s = store.write().await;
        if !s.check_rate(&body.target_mailbox, cost) {
            return Err(rate_limited());
        }
    }
    let ttl = if item_type == ItemType::Request {
        REQUEST_TTL_SEC
    } else {
        MESSAGE_TTL_SEC
    };
    let now = now_secs();
    // item_id = mailbox_id + random suffix (не timestamp!) — избегаем коллизий
    // при массовой записи в одну секунду. 16 случайных байт = 128 бит.
    let suffix = hex::encode(crate::store::random_bytes(16));
    let item_id = format!("{}-{}", body.target_mailbox, suffix);
    let item = QueueItem {
        item_id: item_id.clone(),
        envelope_hex: body.envelope_hex,
        arrived_at: now,
        expires_at: now + ttl,
        item_type,
        acked: false,
    };
    let mut s = store.write().await;
    s.enqueue(&body.target_mailbox, item)
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, e.to_string()))?;
    Ok(Json(EnqueueResponse {
        item_id,
        expires_at: now + ttl,
    }))
}

pub async fn pull(
    State(store): State<SharedStore>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PullResponse>, (StatusCode, String)> {
    let mut s = store.write().await;
    // AUDIT MIN-01: лимит ДО проверки токена — перебор pull_token капится.
    // (check_rate требует &mut self, поэтому до get_mut.)
    if !s.check_rate(&mailbox_id, op_cost::PULL) {
        return Err(rate_limited());
    }
    let mb = s.get_mut(&mailbox_id).ok_or_else(mailbox_not_found)?;
    let token = extract_token(&headers).ok_or_else(forbidden)?;
    if !mb.check_token(token) {
        return Err(forbidden());
    }
    s.prune_expired(now_secs());
    // Перечитываем после prune — mailbox мог измениться.
    let mb = s.get(&mailbox_id).unwrap();
    let items = mb
        .queue
        .iter()
        .filter(|q| !q.acked)
        .map(|q| PullItem {
            item_id: q.item_id.clone(),
            envelope_hex: q.envelope_hex.clone(),
            item_type: match q.item_type {
                ItemType::Request => "request",
                ItemType::Message => "message",
                ItemType::Control => "control",
            }
            .into(),
            arrived_at: q.arrived_at,
            expires_at: q.expires_at,
        })
        .collect::<Vec<_>>();
    Ok(Json(PullResponse { items }))
}

pub async fn ack_handler(
    State(store): State<SharedStore>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AckRequest>,
) -> Result<Json<AckResponse>, (StatusCode, String)> {
    let mut s = store.write().await;
    // AUDIT MIN-01: лимит ДО проверки токена (порядок заимствований + анти-брутфорс).
    if !s.check_rate(&mailbox_id, op_cost::ACK) {
        return Err(rate_limited());
    }
    let mb = s.get_mut(&mailbox_id).ok_or_else(mailbox_not_found)?;
    let token = extract_token(&headers).ok_or_else(forbidden)?;
    if !mb.check_token(token) {
        return Err(forbidden());
    }
    let mut count = 0;
    for id in &body.item_ids {
        if s.ack(&mailbox_id, id) {
            count += 1;
        }
    }
    Ok(Json(AckResponse { acked: count }))
}

pub async fn version() -> impl IntoResponse {
    Json(VersionResponse {
        protocol_version: PROTOCOL_VERSION,
        relay: "min-relay-mock/0.1".into(),
    })
}
