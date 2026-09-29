//! MIN App — высокоуровневый API приложения поверх ядра.
//!
//! Единая точка, через которую UI (Swift) работает с мессенджером:
//! identity + сессии (PQXDH) + delivery (relay) + storage (история) + контакты.
//! В модель UI не утекает ничего криптографического.
//!
//! Контракт для UI описан в CONTRIBUTING.md.

pub mod core;
pub mod ctrl;
pub mod error;
pub mod first_msg;
pub mod model;
pub mod recovery;
pub mod reply;

pub use core::AppCore;
pub use error::{AppError, AppResult};
pub use model::{Chat, Contact, ContactState, Message, MessageStatus};
