/// MIN Session — PQXDH + Double Ratchet session management.
///
/// This crate provides session establishment and message encryption
/// using the Signal Protocol (via libsignal-protocol crate).
///
/// Features:
/// - PQXDH handshake for session initialization (X25519 + ML-KEM-1024)
/// - Double Ratchet for per-message key derivation
/// - Forward secrecy and break-in recovery
/// - Out-of-order message handling (skipped message keys, via libsignal)

/// Re-export the session manager and its public types.
pub mod manager;
pub use manager::FirstContact;
pub use manager::{PreKeyBundleData, SessionError, SessionManager};
pub use manager::{MAX_PREKEY_BUNDLE_CBOR, MAX_PREKEY_BUNDLE_HEX};
