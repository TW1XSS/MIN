//! MIN Contact Request flow (ТЗ §8, §33): state machine + local inbox.
//!
//! Никакой визуализации — только логика. UI подключится позже.

use min_protocol::envelope::MessageType;

pub mod store;

/// Состояния контакта (ТЗ §33). Переходы строго регламентированы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ContactState {
    Unknown,
    OutgoingRequest,
    IncomingRequest,
    Accepted,
    Rejected,
    Blocked,
    Verified,
    KeyChanged,
}

/// Политика приёма новых контактов (ТЗ §8.1, §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactPolicy {
    /// Beta: REQUEST принимается автоматически (ТЗ §44 этап 4).
    AutoAccept,
    /// Prod: ручной accept/reject/block через inbox.
    ManualInbox,
}

/// Настройка «Кто может связываться со мной» (ТЗ §8.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discoverability {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequest {
    pub request_id: String,
    pub sender_identity_ref: String,
    pub state: ContactState,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidTransition,
    ContactBlocked,
    ContactNotAllowed,
    QueueFull,
}

pub type RequestResult<T> = Result<T, RequestError>;

/// Проверяет допустимость перехода (ТЗ §33).
pub fn is_valid_transition(from: ContactState, to: ContactState) -> bool {
    use ContactState::*;
    matches!(
        (from, to),
        (Unknown, OutgoingRequest)
            | (Unknown, IncomingRequest)
            | (IncomingRequest, Accepted)
            | (IncomingRequest, Rejected)
            | (IncomingRequest, Blocked)
            | (Accepted, Verified)
            | (Accepted, KeyChanged)
            | (Accepted, Blocked)
            | (Verified, KeyChanged)
            | (Verified, Blocked)
            | (Blocked, Unknown)
    )
}

pub fn transition(current: ContactState, target: ContactState) -> RequestResult<ContactState> {
    if !is_valid_transition(current, target) {
        return Err(RequestError::InvalidTransition);
    }
    Ok(target)
}

/// Обрабатывает входящий Contact Request согласно политике (ТЗ §8.2).
pub fn handle_incoming_request(
    policy: ContactPolicy,
    discoverability: Discoverability,
    current: ContactState,
) -> RequestResult<ContactState> {
    if current == ContactState::Blocked {
        return Err(RequestError::ContactBlocked);
    }
    if discoverability == Discoverability::Denied {
        return Err(RequestError::ContactNotAllowed);
    }
    // Всегда сначала переходим в IncomingRequest (ТЗ §33), затем — по политике.
    let incoming = transition(current, ContactState::IncomingRequest)?;
    match policy {
        ContactPolicy::AutoAccept => {
            // Beta: автоматически принимаем (IncomingRequest → Accepted).
            transition(incoming, ContactState::Accepted)
        }
        ContactPolicy::ManualInbox => Ok(incoming),
    }
}

pub fn accept_request(current: ContactState) -> RequestResult<ContactState> {
    transition(current, ContactState::Accepted)
}

pub fn reject_request(current: ContactState) -> RequestResult<ContactState> {
    transition(current, ContactState::Rejected)
}

pub fn block_contact(current: ContactState) -> RequestResult<ContactState> {
    transition(current, ContactState::Blocked)
}

pub fn unblock_contact(current: ContactState) -> RequestResult<ContactState> {
    transition(current, ContactState::Unknown)
}

pub fn request_envelope_type() -> MessageType {
    MessageType::Request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_accept_flow() {
        let s = handle_incoming_request(
            ContactPolicy::AutoAccept,
            Discoverability::Allowed,
            ContactState::Unknown,
        )
        .unwrap();
        assert_eq!(s, ContactState::Accepted);
    }

    #[test]
    fn manual_inbox_flow() {
        let s = handle_incoming_request(
            ContactPolicy::ManualInbox,
            Discoverability::Allowed,
            ContactState::Unknown,
        )
        .unwrap();
        assert_eq!(s, ContactState::IncomingRequest);
        assert_eq!(accept_request(s).unwrap(), ContactState::Accepted);
    }

    #[test]
    fn blocked_contact_is_dropped() {
        assert_eq!(
            handle_incoming_request(
                ContactPolicy::AutoAccept,
                Discoverability::Allowed,
                ContactState::Blocked
            )
            .unwrap_err(),
            RequestError::ContactBlocked
        );
    }

    #[test]
    fn denied_discoverability_suppresses() {
        assert_eq!(
            handle_incoming_request(
                ContactPolicy::ManualInbox,
                Discoverability::Denied,
                ContactState::Unknown
            )
            .unwrap_err(),
            RequestError::ContactNotAllowed
        );
    }

    #[test]
    fn invalid_transition_rejected() {
        assert!(!is_valid_transition(
            ContactState::Unknown,
            ContactState::Verified
        ));
        assert_eq!(
            transition(ContactState::Unknown, ContactState::Verified).unwrap_err(),
            RequestError::InvalidTransition
        );
    }

    #[test]
    fn block_and_unblock() {
        assert_eq!(
            block_contact(ContactState::Accepted).unwrap(),
            ContactState::Blocked
        );
        assert_eq!(
            unblock_contact(ContactState::Blocked).unwrap(),
            ContactState::Unknown
        );
    }
}
