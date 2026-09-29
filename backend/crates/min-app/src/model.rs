//! Модель данных, которую видит UI (сериализуется в JSON для FFI).
//!
//! Правило: здесь ничего криптографического — только то, что можно показать
//! в интерфейсе. Ключи/токены/снапшоты живут во внутренних слоях.

use serde::{Deserialize, Serialize};

/// Статус исходящего сообщения (локальная модель, не wire-поле).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    /// Лежит в локальном логе, ещё не ушло на relay (оптимистичный UI).
    Sending,
    /// Relay принял в очередь (есть item_id).
    Sent,
    /// Получатель забрал (пришёл ACK через его pull).
    Delivered,
    /// Отправка не удалась; в UI — «повторить».
    Failed,
}

/// Состояние контакта (переходы — min-request, ТЗ §33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactState {
    Pending,
    Accepted,
    Rejected,
    Blocked,
}

/// Сообщение в локальном логе.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// id позиции на relay (для ack); None, пока не ушло на relay.
    pub item_id: Option<String>,
    /// Локальный ключ контакта (identity hex собеседника).
    pub peer: String,
    pub outgoing: bool,
    pub text: String,
    pub sent_at: u64,
    pub status: MessageStatus,
    /// CONTROL-ответ получателя на заявку (MIN-RED-022): `"accepted"` /
    /// `"not_delivered"`. `None` — обычное сообщение.
    ///
    /// На проводе ровно ДВА кода без причины (см. `ctrl`): различать
    /// «отклонено / заблокировано / заявки выключены» нельзя — это выдало бы
    /// решение получателя. UI под этот случай ещё не готов, но данные уже
    /// доступны, чтобы экран заявок заработал без правок ядра.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    /// Цитата ответа: кому и на что отвечает это сообщение.
    ///
    /// Живёт в зашифрованном payload (см. `reply`), поэтому цитата видна обеим
    /// сторонам и переживает перезапуск. До этого reply существовал только
    /// в UI: цитата рисовалась локально и терялась при первом же reloadChats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<ReplyRef>,
}

/// Часть сообщения, на которую отвечают.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplyRef {
    /// Отображаемое имя автора цитируемого сообщения.
    pub author: String,
    /// Сокращённый текст цитируемого сообщения (для «плашки» в пузыре).
    pub preview: String,
}

/// Контакт (локальная запись адресной книги).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contact {
    pub name: String,
    /// Ed25519 identity собеседника (hex) — локальный ключ записей.
    pub identity_hex: String,
    pub mailbox_id_hex: String,
    pub epoch: u64,
    pub state: ContactState,
}

/// Чат в списке (агрегат по peer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub peer: String,
    pub name: String,
    pub last_text: String,
    pub last_at: u64,
    pub unread: u32,
}
