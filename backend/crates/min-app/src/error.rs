//! Ошибки высокоуровневого API приложения (`min-app`).
//!
//! Наружу (в FFI/Swift) уходит строка; внутри — типизированные варианты,
//! чтобы отлаживать было можно, а UI не приходилось разбирать коды.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("session: {0}")]
    Session(String),
    #[error("delivery: {0}")]
    Delivery(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("contact not found: {0}")]
    ContactNotFound(String),
    #[error("contact blocked")]
    ContactBlocked,
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
}

pub type AppResult<T> = Result<T, AppError>;

impl From<min_storage::StorageError> for AppError {
    fn from(e: min_storage::StorageError) -> Self {
        AppError::Storage(e.to_string())
    }
}

impl From<min_session::SessionError> for AppError {
    fn from(e: min_session::SessionError) -> Self {
        AppError::Session(e.to_string())
    }
}

impl From<min_delivery::DeliveryError> for AppError {
    fn from(e: min_delivery::DeliveryError) -> Self {
        AppError::Delivery(e.to_string())
    }
}

impl From<min_protocol::ProtocolError> for AppError {
    fn from(e: min_protocol::ProtocolError) -> Self {
        AppError::Protocol(e.to_string())
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> Self {
        AppError::Protocol(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Json(e.to_string())
    }
}
