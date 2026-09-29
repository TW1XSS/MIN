//! Session manager on top of libsignal-protocol (PQXDH + Double Ratchet).
//!
//! Security policy (README: «только проверенная криптография»):
//! NO hand-written ratchet. Session establishment and message ratcheting
//! are delegated entirely to libsignal-protocol (the audited Signal
//! Protocol implementation used by Signal clients).
//!
//! This module is a thin, panic-free adapter:
//! - X25519 identity + SignedPreKey + OneTimePreKey + ML-KEM-1024 (PQXDH)
//! - async libsignal calls are executed on a local executor (block_on)
//! - session state lives in InMemSignalProtocolStore for MVP; persistence
//!   arrives with the storage phase (wire record serialization is available
//!   via SessionRecord::serialize()).

use futures_executor::block_on;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, SessionRecord, SessionStore, SignalMessage, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};

use thiserror::Error;

/// Errors that can occur during session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid prekey bundle")]
    InvalidPrekeyBundle,
    #[error("session already exists: {0}")]
    SessionExists(String),
    #[error("ratchet error: {0}")]
    Ratchet(String),
    #[error("skipped message key limit exceeded")]
    SkippedKeyLimitExceeded,
    /// RT-26.2: restore из snapshot'а отозванного устройства/identity.
    #[error("identity fingerprint is revoked (stale backup rejected)")]
    RevokedIdentity,
    /// MIN-26 / RT-26.9: адрес пира выведен из устаревшей эпохи Contact Key
    /// (ротация) либо попытка откатить/подменить эпоху — маршрут закрыт.
    #[error("peer contact key epoch is stale or rolled back")]
    EpochRotated,
}

/// Result type for session operations.
pub type SessionResult<T> = Result<T, SessionError>;

/// Hard input cap for one signed prekey bundle. A valid ML-KEM-1024 bundle is
/// roughly 2–3 KiB; 16 KiB leaves migration headroom while preventing an
/// attacker-controlled invite from allocating/cryptographically hashing an
/// arbitrarily large CBOR value on the device.
pub const MAX_PREKEY_BUNDLE_CBOR: usize = 16 * 1024;
/// Hex transport is exactly two ASCII characters per CBOR byte.
pub const MAX_PREKEY_BUNDLE_HEX: usize = MAX_PREKEY_BUNDLE_CBOR * 2;

/// Результат принятия первого сообщения от незнакомца (MIN-RED-022).
///
/// `peer_identity` проверен libsignal'ом при расшифровке PreKey-сообщения:
/// сессия создаётся только если подпись identity согласована с prekey'ом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstContact {
    /// Адресное имя пира в нашем соглашении = hex публичного identity.
    pub peer_name: String,
    /// Ed25519 identity отправителя (32 байта).
    pub peer_identity: [u8; 32],
    /// Расшифрованное содержимое первого сообщения.
    pub plaintext: Vec<u8>,
}

/// Transport-serializable copy of a peer's PreKeyBundle.
///
/// All keys are libsignal `serialize()` forms; this is what the prekey
/// publication (relay bundle fetch, MVP) carries. Relay sees only these
/// opaque bytes. CBOR transport form is deterministic (struct field order).
///
/// NOTE: this structure is NOT part of the frozen PROTOCOL.md wire format —
/// it is the prekey-publication payload. Verification happens against the
/// identity key from the frozen Contact Key v3 (signature checks enforced
/// by libsignal `process_prekey_bundle`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreKeyBundleData {
    pub registration_id: u32,
    pub device_id: u32,
    pub pre_key_id: u32,
    pub pre_key_public: Vec<u8>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: Vec<u8>,
    pub signed_pre_key_signature: Vec<u8>,
    pub identity_key: Vec<u8>,
    pub kyber_pre_key_id: u32,
    pub kyber_pre_key_public: Vec<u8>,
    pub kyber_pre_key_signature: Vec<u8>,
    /// Ed25519 binding to the Contact Key identity. This is not part of the
    /// frozen envelope/Contact Key wire; it authenticates the prekey publication
    /// against the long-term identity before libsignal consumes it.
    #[serde(default)]
    pub contact_key_binding: Option<Vec<u8>>,
}

impl PreKeyBundleData {
    /// Bytes authenticated by `contact_key_binding`: every public prekey field,
    /// excluding the binding itself. Domain-separated from Contact Key v3.
    pub fn contact_key_binding_payload(&self) -> SessionResult<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct Payload<'a> {
            registration_id: u32,
            device_id: u32,
            pre_key_id: u32,
            pre_key_public: &'a [u8],
            signed_pre_key_id: u32,
            signed_pre_key_public: &'a [u8],
            signed_pre_key_signature: &'a [u8],
            identity_key: &'a [u8],
            kyber_pre_key_id: u32,
            kyber_pre_key_public: &'a [u8],
            kyber_pre_key_signature: &'a [u8],
        }
        let payload = Payload {
            registration_id: self.registration_id,
            device_id: self.device_id,
            pre_key_id: self.pre_key_id,
            pre_key_public: &self.pre_key_public,
            signed_pre_key_id: self.signed_pre_key_id,
            signed_pre_key_public: &self.signed_pre_key_public,
            signed_pre_key_signature: &self.signed_pre_key_signature,
            identity_key: &self.identity_key,
            kyber_pre_key_id: self.kyber_pre_key_id,
            kyber_pre_key_public: &self.kyber_pre_key_public,
            kyber_pre_key_signature: &self.kyber_pre_key_signature,
        };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&payload, &mut out)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        let mut domain = b"MIN-CONTACT-BUNDLE-BINDING-v1\0".to_vec();
        domain.extend_from_slice(&out);
        Ok(domain)
    }

    /// Sign all prekey publication fields with the long-term Ed25519 identity.
    pub fn bind_contact_key(&mut self, identity_secret: &[u8; 32]) -> SessionResult<()> {
        let identity = min_identity::IdentityKeypair::from_secret_bytes(identity_secret);
        let payload = self.contact_key_binding_payload()?;
        self.contact_key_binding = Some(identity.sign(&payload).to_vec());
        Ok(())
    }

    /// Verify the binding against the Contact Key identity.
    pub fn verify_contact_key_binding(&self, identity_public: &[u8; 32]) -> bool {
        let Some(signature) = self.contact_key_binding.as_deref() else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        self.contact_key_binding_payload()
            .map(|payload| {
                min_identity::IdentityKeypair::verify(identity_public, &payload, &signature)
            })
            .unwrap_or(false)
    }

    /// Deterministic CBOR encoding (struct field order).
    pub fn to_cbor(&self) -> SessionResult<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        Ok(buf)
    }

    /// Strict decode: bounded input, unknown fields and trailing bytes rejected.
    pub fn from_cbor(bytes: &[u8]) -> SessionResult<Self> {
        if bytes.len() > MAX_PREKEY_BUNDLE_CBOR {
            return Err(crate::SessionError::InvalidPrekeyBundle);
        }
        let mut cursor = std::io::Cursor::new(bytes);
        let value = ciborium::de::from_reader(&mut cursor)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        // Ensure no trailing garbage remains.
        let pos = cursor.position() as usize;
        if pos != bytes.len() {
            return Err(crate::SessionError::Crypto(
                "trailing bytes in bundle".into(),
            ));
        }
        Ok(value)
    }
}

/// One peer's crypto persona: full protocol store + address.
///
/// MVP runs every peer in-process for tests; the FFI facade (phase B3)
/// exposes one SessionManager per app identity, which is what a real
/// client uses.
pub struct SessionManager {
    store: InMemSignalProtocolStore,
    #[allow(dead_code)]
    local_name: String,
    /// Known peers (для snapshot-энумерации: InMemSessionStore не итерируется).
    pub(crate) peers: std::collections::BTreeSet<String>,
    /// AUDIT RT-2/RT-3f: анти-abuse состояние per peer. PROTOCOL §73 требует
    /// skipped-key cap 100 → SUSPICIOUS и остывание после 3 фейлов — раньше
    /// это было декларацией без реализации (libsignal по умолчанию терпит
    /// произвольные гэпы и бесконечные неудачные расшифровки).
    guards: std::collections::HashMap<String, PeerGuard>,
    /// MIN-26 / RT-26.9: эпохи Contact Key по identity пира:
    /// hex(identity_public_key) -> (peer_address, epoch). Ротация повышает
    /// epoch и закрывает прежний адрес; понижение (rollback) отвергается.
    peer_epochs: std::collections::BTreeMap<String, (String, u64)>,
    /// MIN-26: адреса устаревших эпох — маршрутизация закрыта
    /// (encrypt/decrypt/init_session отказывают).
    stale_addresses: std::collections::BTreeSet<String>,
}

/// Анти-abuse состояние сессии с одним peer.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct PeerGuard {
    /// Ожидаемый минимальный ratchet-counter следующего сообщения.
    /// `None` — сессия ещё не расшифровала ни одного whisper-сообщения,
    /// база неизвестна (MIN-18: раньше дефолт 0 давал ложные срабатывания).
    next_counter: Option<u32>,
    /// Подряд неудачных расшифровок.
    fail_streak: u32,
    /// Unix-секунды, до которых сессия «остывает» (SUSPICIOUS).
    cooling_until: u64,
    /// MIN-18: сколько раз гэп-кап пересинхронизировал базу (телеметрия).
    resyncs: u32,
}

/// Skipped-message-key cap (PROTOCOL §73): гэп ratchet-counter'ов больше
/// этого → session считается SUSPICIOUS, расшифровка не выполняется.
const SKIPPED_KEY_CAP: u32 = 100;

/// RT-26.13: чистая wrap-safe арифметика гэпа. Backward-counter (counter <
/// base) и u32-rollover не должны порождать ложных срабатываний капа:
/// saturating_sub клампит в 0, переполнения нет по построению.
fn gap_exceeds_cap(counter: u32, base: u32) -> bool {
    counter.saturating_sub(base) >= SKIPPED_KEY_CAP
}
/// Подряд неудачных расшифровок до остывания (PROTOCOL §73).
const MAX_FAIL_STREAK: u32 = 3;
/// Длительность остывания, секунды.
const COOLING_SECS: u64 = 60;

/// Ратчет-counter сообщения (MIN-18): есть у whisper и у внутреннего
/// message PreKey-конверта. `None` — тип без counter'а.
fn ratchet_counter(msg: &CiphertextMessage) -> Option<u32> {
    match msg {
        CiphertextMessage::SignalMessage(m) => Some(m.counter()),
        CiphertextMessage::PreKeySignalMessage(m) => Some(m.message().counter()),
        _ => None,
    }
}

fn now_millis() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Timestamp::from_epoch_millis(millis)
}

/// Unix-секунды (для анти-abuse-логики PeerGuard).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now() -> SystemTime {
    SystemTime::now()
}

/// Address book convention: one device per peer name, device_id = 1.
/// libsignal сериализует публичный ключ Ed25519 как `0x05 || pk[32]`
/// (DER-префикс типа). Наше адресное соглашение — hex «сырых» 32 байт, поэтому
/// префикс снимается здесь. Префикс != 0x05 означает заявленный не-Ed25519
/// ключ: наш протокол использует только Ed25519 (PROTOCOL §0), такой отвергаем.
fn raw_identity_from_serialized(public: &[u8]) -> Option<[u8; 32]> {
    match public.split_first() {
        Some((0x05, raw)) if raw.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(raw);
            Some(out)
        }
        _ => None,
    }
}

/// Заявленный identity из PreKey-сообщения — БЕЗ расшифровки (MIN-RED-022).
///
/// Возвращает `None`, если это не PreKey-конверт или identity заявлен не как
/// Ed25519. **Значение не проверено**: подпись проверяется только внутри
/// `accept_from_stranger` (libsignal). Поэтому результат годится ровно для
/// трёх вещей: показать карточку заявки, применить блок-лист и не плодить
/// дубликаты заявок. Принимать контакт, создавать сессию или показывать текст
/// по нему нельзя — для этого `accept_from_stranger`.
pub fn peek_stranger_identity(envelope: &[u8]) -> Option<[u8; 32]> {
    let (type_byte, body) = envelope.split_first()?;
    if *type_byte != 0x01 {
        return None;
    }
    let msg = PreKeySignalMessage::try_from(body).ok()?;
    let public = msg.identity_key().public_key().serialize();
    raw_identity_from_serialized(&public)
}

fn address_of(name: &str) -> ProtocolAddress {
    // libsignal 0.102 (MIN-16): device id — typed DeviceId, checked at construction.
    ProtocolAddress::new(name.to_owned(), DeviceId::new(1).unwrap())
}

impl SessionManager {
    /// Creates a manager with a fresh X25519 identity.
    pub fn new(local_name: &str) -> SessionResult<Self> {
        let mut csprng = rand_core::UnwrapErr(rand_core::OsRng);
        let identity_key_pair = IdentityKeyPair::generate(&mut csprng);
        // Valid registration IDs fit in 14 bits (libsignal invariant).
        let registration_id: u32 = u32::from(csprng.random::<u16>() & 0x3FFF);

        let store = InMemSignalProtocolStore::new(identity_key_pair, registration_id)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        Ok(Self {
            store,
            local_name: local_name.to_owned(),
            peers: std::collections::BTreeSet::new(),
            guards: std::collections::HashMap::new(),
            peer_epochs: std::collections::BTreeMap::new(),
            stale_addresses: std::collections::BTreeSet::new(),
        })
    }

    /// AUDIT RT-2/RT-3f: сессия в остывании (SUSPICIOUS)?
    /// true = расшифровки от этого peer временно отклоняются.
    pub fn is_suspicious(&self, peer_name: &str) -> bool {
        self.guards
            .get(peer_name)
            .map(|g| g.cooling_until > now_secs())
            .unwrap_or(false)
    }

    /// Есть ли сессия с таким адресным именем.
    ///
    /// Нужен вызывающей стороне, чтобы выбрать КЛЮЧ СЕССИИ, а не угадывать:
    /// сессия может быть заведена под одним именем, а контакт в книге —
    /// храниться под другим (например, принятый незнакомец заводится под
    /// hex(identity), а показывается как `User-xxxxxx`). Попытка `decrypt`
    /// с неверным именем вернула бы «нет сессии», и мы бы потеряли сообщение.
    pub fn has_session(&self, peer_name: &str) -> bool {
        self.peers.contains(peer_name)
    }

    /// Тестовый помощник: сбросить анти-abuse состояние (fuzz/диагностика).
    #[cfg(test)]
    pub(crate) fn reset_guards(&mut self) {
        self.guards.clear();
    }

    /// Тестовый помощник: сколько раз гэп-кап пересинхронизировал базу (MIN-18).
    #[cfg(test)]
    pub(crate) fn guard_resyncs(&self, peer_name: &str) -> u32 {
        self.guards.get(peer_name).map(|g| g.resyncs).unwrap_or(0)
    }

    /// Public identity key (libsignal serialize form).
    pub fn identity_key_public(&self) -> Vec<u8> {
        block_on(async {
            self.store
                .get_identity_key_pair()
                .await
                .expect("identity key pair present")
                .identity_key()
                .public_key()
                .serialize()
                .as_ref()
                .to_vec()
        })
    }

    /// Registration id (fits 14 bits, libsignal invariant).
    pub fn registration_id(&self) -> u32 {
        block_on(async { self.store.get_local_registration_id().await })
            .expect("registration id present")
    }

    /// Generates fresh keys for the bundle: one-time prekey + signed prekey +
    /// Kyber (ML-KEM-1024) prekey. All stored in the protocol store; returns
    /// the transport-serializable bundle data.
    pub fn generate_prekey_bundle(&mut self) -> SessionResult<PreKeyBundleData> {
        let mut csprng = rand_core::UnwrapErr(rand_core::OsRng);

        let pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);

        let identity_priv = block_on(async { self.store.get_identity_key_pair().await })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?
            .private_key()
            .clone();

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity_priv
            .calculate_signature(signed_pre_key_public.as_ref(), &mut csprng)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?
            .to_vec();

        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let kyber_pre_key_signature = identity_priv
            .calculate_signature(kyber_pre_key_public.as_ref(), &mut csprng)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?
            .to_vec();

        let pre_key_id: u32 = csprng.random();
        let signed_pre_key_id: u32 = csprng.random();
        let kyber_pre_key_id: u32 = csprng.random();
        let device_id: u32 = 1;

        block_on(async {
            self.store
                .save_pre_key(
                    pre_key_id.into(),
                    &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
                )
                .await?;

            self.store
                .save_signed_pre_key(
                    signed_pre_key_id.into(),
                    &<SignedPreKeyRecord as GenericSignedPreKey>::new(
                        signed_pre_key_id.into(),
                        now_millis(),
                        &signed_pre_key_pair,
                        &signed_pre_key_signature,
                    ),
                )
                .await?;

            self.store
                .save_kyber_pre_key(
                    kyber_pre_key_id.into(),
                    &<KyberPreKeyRecord as GenericSignedPreKey>::new(
                        kyber_pre_key_id.into(),
                        now_millis(),
                        &kyber_pre_key_pair,
                        &kyber_pre_key_signature,
                    ),
                )
                .await?;

            Ok::<(), libsignal_protocol::SignalProtocolError>(())
        })
        .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        Ok(PreKeyBundleData {
            registration_id: self.registration_id(),
            device_id,
            pre_key_id,
            pre_key_public: pre_key_pair.public_key.serialize().as_ref().to_vec(),
            signed_pre_key_id,
            signed_pre_key_public: signed_pre_key_public.as_ref().to_vec(),
            signed_pre_key_signature,
            identity_key: self.identity_key_public(),
            kyber_pre_key_id,
            kyber_pre_key_public: kyber_pre_key_public.as_ref().to_vec(),
            kyber_pre_key_signature,
            contact_key_binding: None,
        })
    }

    /// Rebuilds a libsignal PreKeyBundle from its transport form.
    fn bundle_from_data(data: &PreKeyBundleData) -> SessionResult<PreKeyBundle> {
        use libsignal_protocol::{IdentityKey, KyberPreKeyId, PreKeyId, SignedPreKeyId};

        let identity_key = IdentityKey::new(
            libsignal_protocol::PublicKey::deserialize(data.identity_key.as_slice())
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?,
        );
        let pre_key_public =
            libsignal_protocol::PublicKey::deserialize(data.pre_key_public.as_slice())
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        let signed_pre_key_public =
            libsignal_protocol::PublicKey::deserialize(data.signed_pre_key_public.as_slice())
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        let kyber_public = kem::PublicKey::deserialize(data.kyber_pre_key_public.as_slice())
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        let bundle = PreKeyBundle::new(
            data.registration_id,
            // libsignal 0.102 (MIN-16): DeviceId типизирован (u8) и проверяется.
            DeviceId::new(
                u8::try_from(data.device_id)
                    .map_err(|_| crate::SessionError::InvalidPrekeyBundle)?,
            )
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?,
            Some((PreKeyId::from(data.pre_key_id), pre_key_public)),
            SignedPreKeyId::from(data.signed_pre_key_id),
            signed_pre_key_public,
            data.signed_pre_key_signature.clone(),
            KyberPreKeyId::from(data.kyber_pre_key_id),
            kyber_public,
            data.kyber_pre_key_signature.clone(),
            identity_key,
        )
        .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        Ok(bundle)
    }

    /// Alice-side: establishes a session with `peer_name` from their bundle.
    /// Internal implementation for `init_session_with_contact_key`. Kept private so
    /// production Rust callers cannot bypass the Contact Key binding path.
    fn init_session(&mut self, peer_name: &str, data: &PreKeyBundleData) -> SessionResult<()> {
        // MIN-26: адрес ротированной эпохи — мёртвый маршрут.
        self.ensure_address_live(peer_name)?;
        let bundle = Self::bundle_from_data(data)?;
        let peer_address = address_of(peer_name);
        let mut csprng = rand_core::UnwrapErr(rand_core::OsRng);

        block_on(async {
            // libsignal 0.102 (MIN-16): добавился local_address — PQ-ratchet
            // привязывает состояние ratchet к паре адресов (remote, local).
            process_prekey_bundle(
                &peer_address,
                &address_of(&self.local_name),
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &bundle,
                now(),
                &mut csprng,
            )
            .await
        })
        .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        // AUDIT RT-2/RT-3f: новая сессия — анти-abuse состояние сбрасывается.
        self.guards.remove(peer_name);
        // Persistence (v6): peer регистрируется для snapshot-энумерации.
        self.peers.insert(peer_name.to_owned());

        Ok(())
    }

    /// Encrypts `plaintext` for `peer_name`.
    ///
    /// Returns `[msg_type_byte][libsignal serialized]`:
    /// 0x01 = PreKeySignalMessage (session initiation), 0x02 = SignalMessage
    /// (Double Ratchet). The prefix lets the receiver dispatch deterministically.
    pub fn encrypt(&mut self, peer_name: &str, plaintext: &[u8]) -> SessionResult<Vec<u8>> {
        // MIN-26 / RT-26.9: в адрес устаревшей эпохи не шифруем.
        self.ensure_address_live(peer_name)?;
        let peer_address = address_of(peer_name);
        let mut csprng = rand_core::UnwrapErr(rand_core::OsRng);

        let ciphertext: CiphertextMessage = block_on(async {
            // libsignal 0.102 (MIN-16): local_address + csprng в сигнатуре.
            message_encrypt(
                plaintext,
                &peer_address,
                &address_of(&self.local_name),
                &mut self.store.session_store,
                &mut self.store.identity_store,
                now(),
                &mut csprng,
            )
            .await
        })
        .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        let type_byte: u8 = match ciphertext.message_type() {
            CiphertextMessageType::PreKey => 0x01,
            CiphertextMessageType::Whisper => 0x02,
            other => {
                return Err(crate::SessionError::Crypto(format!(
                    "unexpected message type: {other:?}"
                )))
            }
        };

        let mut out = Vec::with_capacity(1 + ciphertext.serialize().len());
        out.push(type_byte);
        out.extend_from_slice(ciphertext.serialize());
        Ok(out)
    }

    /// Decrypts `ciphertext` from `peer_name` (see `encrypt` wire format).
    pub fn decrypt(&mut self, peer_name: &str, ciphertext: &[u8]) -> SessionResult<Vec<u8>> {
        // MIN-26 / RT-26.9: с закрытого адреса не принимаем (старая сессия
        // не может остаться живой после ротации Contact Key).
        self.ensure_address_live(peer_name)?;
        let peer_address = address_of(peer_name);
        let mut csprng = rand_core::UnwrapErr(rand_core::OsRng);

        let (type_byte, body) = ciphertext
            .split_first()
            .ok_or_else(|| crate::SessionError::Crypto("empty ciphertext".to_owned()))?;

        let msg = match type_byte {
            0x01 => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(body)
                    .map_err(|e| crate::SessionError::Crypto(e.to_string()))?,
            ),
            0x02 => CiphertextMessage::SignalMessage(
                SignalMessage::try_from(body)
                    .map_err(|e| crate::SessionError::Crypto(e.to_string()))?,
            ),
            other => {
                return Err(crate::SessionError::Crypto(format!(
                    "unknown message type byte: {other:#x}"
                )))
            }
        };

        // AUDIT RT-2/RT-3f: анти-abuse гейт (PROTOCOL §73).
        // Прогрев и кап гэпов — до фактической расшифровки.
        self.decrypt_precheck(peer_name, &msg)?;
        // Заимствования разносим: guard обрабатывается до async-блока.
        let mut guard = self.guards.remove(peer_name).unwrap_or_default();
        let result = self.decrypt_inner(&peer_address, &msg, &mut csprng);
        let outcome = match result {
            Ok(pt) => {
                // Успех: ratchet сдвинулся, счётчики фейлов и остывание сбрасываются.
                guard.fail_streak = 0;
                guard.cooling_until = 0;
                if let CiphertextMessage::SignalMessage(m) = &msg {
                    guard.next_counter = Some(m.counter().saturating_add(1));
                } else if let CiphertextMessage::PreKeySignalMessage(m) = &msg {
                    // MIN-18: PreKey-конверт несёт внутренний counter (обычно 0);
                    // без установки базы кап гэпов не работал вовсе.
                    guard.next_counter = Some(m.message().counter().saturating_add(1));
                }
                // Persistence (v6): peer (Bob-сторона) регистрируется при первом
                // успешном decrypt — сессия создана libsignal'ом из PreKey-сообщения.
                self.peers.insert(peer_name.to_owned());
                Ok(pt)
            }
            Err(e) => {
                guard.fail_streak = guard.fail_streak.saturating_add(1);
                if guard.fail_streak >= MAX_FAIL_STREAK {
                    // 3 неудачные расшифровки подряд → SUSPICIOUS (остывание).
                    guard.cooling_until = now_secs().saturating_add(COOLING_SECS);
                    guard.fail_streak = 0;
                }
                Err(e)
            }
        };
        self.guards.insert(peer_name.to_owned(), guard);
        outcome
    }

    /// Прогрев-гейт и кап гэпов ratchet-counter'ов — до фактической расшифровки.
    ///
    /// AUDIT MIN-18: relay, дропающий сообщения, может форсировать большой гэп.
    /// Прежняя логика возвращала ошибку, не сдвигая базу → сессия НАВСЕГДА
    /// отвергала все последующие whisper-сообщения (DoS на доступность).
    /// Теперь такой envelope отклоняется (защита skipped-key storage), но база
    /// пересинхронизируется на наблюдаемый counter: следующий envelope
    /// (counter+1) имеет гэп 1 и принимается.
    fn decrypt_precheck(&mut self, peer_name: &str, msg: &CiphertextMessage) -> SessionResult<()> {
        let cooling = self
            .guards
            .get(peer_name)
            .map(|g| g.cooling_until > now_secs())
            .unwrap_or(false);
        if cooling {
            return Err(crate::SessionError::Ratchet(
                "session SUSPICIOUS: cooling after repeated failures".into(),
            ));
        }
        // Skipped-key cap (PROTOCOL §73): гэп counter'ов > 100 → SUSPICIOUS.
        // MIN-18: counter есть и у PreKey-конверта (внутренний message),
        // поэтому кап применяется к обоим типам. База неизвестна (None) →
        // гэп не с чем сравнивать (первое сообщение сессии).
        if let Some(counter) = ratchet_counter(msg) {
            let base = self.guards.get(peer_name).and_then(|g| g.next_counter);
            if let Some(base) = base {
                if gap_exceeds_cap(counter, base) {
                    let guard = self.guards.entry(peer_name.to_owned()).or_default();
                    guard.next_counter = Some(counter);
                    guard.resyncs = guard.resyncs.saturating_add(1);
                    return Err(crate::SessionError::SkippedKeyLimitExceeded);
                }
            }
        }
        Ok(())
    }

    /// Собственно расшифровка (без анти-abuse логики).
    fn decrypt_inner(
        &mut self,
        peer_address: &ProtocolAddress,
        msg: &CiphertextMessage,
        csprng: &mut rand_core::UnwrapErr<rand_core::OsRng>,
    ) -> SessionResult<Vec<u8>> {
        block_on(async {
            // libsignal 0.102 (MIN-16): добавился local_address в сигнатуре.
            message_decrypt(
                msg,
                peer_address,
                &address_of(&self.local_name),
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &mut self.store.pre_key_store,
                &self.store.signed_pre_key_store,
                &mut self.store.kyber_pre_key_store,
                csprng,
            )
            .await
        })
        .map_err(|e| crate::SessionError::Crypto(e.to_string()))
    }

    /// Забывает сессию с пиром (MIN-RED-022, Reject/Block).
    ///
    /// Сессия не удаляется из in-memory store libsignal (нет публичного API),
    /// но `self.peers` — источник истины для `snapshot()`: имя исчезает из
    /// снапшота, а значит и из recovery-боба, и из Keychain. Именно это и нужно:
    /// заявка отброшена, её сессия не должна ни расти, ни переживать перезапуск,
    /// ни попадать в восстановление как «контакт». Сама запись в RAM остаётся
    /// (сотни байт) — освободить её без поддержки delete_session нельзя, но
    /// создаётся она только по ЯВНОМУ действию пользователя (Accept/Reject/Block),
    /// а не по каждому входящему конверту, поэтому потолок задаёт человек.
    pub fn forget_peer(&mut self, peer_name: &str) -> bool {
        if !self.peers.contains(peer_name) {
            return false;
        }
        self.peers.remove(peer_name);
        self.guards.remove(peer_name);
        self.peer_epochs.remove(peer_name);
        self.stale_addresses.remove(peer_name);
        true
    }

    /// MIN-RED-022: первое сообщение от НЕЗНАКОМЦА.
    ///
    /// Обычный `decrypt(peer_name, …)` перебирает известные контакты, поэтому
    /// конверт от незнакомца не проходит: адрес отправителя заранее неизвестен.
    /// Здесь он берётся из самого PreKey-сообщения — libsignal достаёт identity
    /// отправителя из protobuf и **проверяет подпись** этого identity при
    /// обработке сообщения. Своей криптографии здесь нет: session создаётся
    /// внутри `message_decrypt` (см. комментарий в исходниках libsignal:
    /// *«A PreKey message creates a session and then decrypts a Whisper
    /// message using that session»).
    ///
    /// Возвращает identity, mailbox (для ответа) и plaintext.
    ///
    /// ВАЖНО ДЛЯ ПАМЯТИ: метод создаёт полноценную сессию, а значит запись
    /// попадает в `snapshot()` → recovery-блоб → Keychain (лимит 48 КиБ).
    /// Вызывать ТОЛЬКО при явном Accept пользователя, а не на каждый
    /// входящий конверт, иначе двадцать незнакомцев раздуют блоб.
    pub fn accept_from_stranger(&mut self, envelope: &[u8]) -> SessionResult<FirstContact> {
        let (type_byte, body) = envelope
            .split_first()
            .ok_or_else(|| crate::SessionError::Crypto("empty ciphertext".to_owned()))?;

        // Whisper-сообщение без сессии расшифровать нельзя: инициатор
        // неизвестен. Тип 0x02 здесь — не «злоумышленник», а просто
        // «это не первое сообщение».
        if *type_byte != 0x01 {
            return Err(crate::SessionError::Crypto(format!(
                "stranger message must be PreKey, got {type_byte:#x}"
            )));
        }
        let msg = PreKeySignalMessage::try_from(body)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;

        // Заявленный отправитель. Он ещё НЕ проверен — проверка подписи
        // identity произойдёт внутри message_decrypt, и при несовпадении
        // сессия не создастся.
        let identity = *msg.identity_key();
        let public = identity.public_key().serialize();
        // Префикс 0x05 (Ed25519) снимается единым хелпером — тем же, что и в
        // `peek_stranger_identity`, чтобы «заявленный» и «проверенный» пути к
        // identity не могли разойтись.
        let peer_bytes = raw_identity_from_serialized(&public).ok_or_else(|| {
            crate::SessionError::Crypto(format!(
                "stranger identity is not Ed25519: prefix/len {public:?}"
            ))
        })?;
        // Адресное соглашение проекта: имя пира = hex публичного identity.
        let peer_name = hex::encode(peer_bytes);

        let mut csprng = rand_core::UnwrapErr(rand_core::OsRng);
        let peer_address = address_of(&peer_name);

        // Базовый счётчик берём из внутреннего counter'а PreKey ДО перемещения
        // `msg` в enum: без этого (MIN-18) первый же последующий whisper-конверт
        // от собеседника выглядел бы как огромный гэп и был бы отвергнут.
        let inner_counter = msg.message().counter().saturating_add(1);

        let envelope_msg = CiphertextMessage::PreKeySignalMessage(msg);
        let plaintext = self.decrypt_inner(&peer_address, &envelope_msg, &mut csprng)?;

        // Сессия создана — пир становится известным (иначе не попадёт в
        // снапшот, и следующие конверты от него не расшифруются).
        let mut guard = self.guards.remove(&peer_name).unwrap_or_default();
        guard.fail_streak = 0;
        guard.cooling_until = 0;
        guard.next_counter = Some(inner_counter);
        self.guards.insert(peer_name.clone(), guard);
        self.peers.insert(peer_name.clone());

        Ok(FirstContact {
            peer_name,
            peer_identity: peer_bytes,
            plaintext,
        })
    }

    /// MIN-RED-022: отправить контакту, которого ещё нет. Сессия поднимается
    /// по его Contact Key, первое сообщение уходит как PreKey-сообщение
    /// (оно само несёт identity и prekey получателя, поэтому ответчик сможет
    /// установить сессию в одну сторону, без нашего предварительного контакта).
    pub fn init_session_from_invite(
        &mut self,
        identity_hex: &str,
        peer_name: &str,
        epoch: u64,
        data: &PreKeyBundleData,
    ) -> SessionResult<bool> {
        self.init_session_with_contact_key(identity_hex, peer_name, epoch, data)
    }

    // ---- MIN-26: ротация адреса (epoch Contact Key) --------------------

    /// Привязывает Contact Key пира к его identity: адрес — функция от
    /// (identity, epoch), поэтому новая эпоха = новый адрес, а прежний
    /// закрывается. `true` = это была ротация (адрес сменился).
    ///
    /// FAIL-CLOSED (RT-26.9):
    /// - epoch < EPOCH_INITIAL → `EpochRotated`;
    /// - epoch ниже известного → `EpochRotated` (rollback Contact Key);
    /// - та же эпоха, другой адрес → `EpochRotated` (адрес не выводится из
    ///   identity+epoch — расхождение с PROTOCOL §5).
    pub fn bind_contact_key_epoch(
        &mut self,
        identity_hex: &str,
        peer_name: &str,
        epoch: u64,
    ) -> SessionResult<bool> {
        if epoch < min_identity::EPOCH_INITIAL {
            return Err(SessionError::EpochRotated);
        }
        match self.peer_epochs.get(identity_hex).cloned() {
            None => {
                self.peer_epochs
                    .insert(identity_hex.to_owned(), (peer_name.to_owned(), epoch));
                Ok(false)
            }
            Some((known_peer, known_epoch)) => {
                if epoch == known_epoch {
                    return if known_peer == peer_name {
                        Ok(false)
                    } else {
                        Err(SessionError::EpochRotated)
                    };
                }
                if epoch < known_epoch {
                    // Откат (в том числе возврат старого Contact Key) — отказ.
                    return Err(SessionError::EpochRotated);
                }
                // Ротация: прежний адрес закрыт навсегда.
                self.stale_addresses.insert(known_peer);
                self.stale_addresses.remove(peer_name);
                self.peer_epochs
                    .insert(identity_hex.to_owned(), (peer_name.to_owned(), epoch));
                Ok(true)
            }
        }
    }

    /// MIN-26: адрес закрыт ротацией (маршрут мёртв)?
    pub fn is_stale_address(&self, peer_name: &str) -> bool {
        self.stale_addresses.contains(peer_name)
    }

    /// MIN-26: всякий доступ к сессии проходит через эту проверку.
    fn ensure_address_live(&self, peer_name: &str) -> SessionResult<()> {
        if self.is_stale_address(peer_name) {
            return Err(SessionError::EpochRotated);
        }
        Ok(())
    }

    /// MIN-26 / RT-26.9: инициализация сессии с привязкой к эпохе Contact Key.
    /// Прежний адрес закрывается ДО установления новой сессии, поэтому
    /// «старая сессия осталась живой после ротации» невозможно.
    pub fn init_session_with_contact_key(
        &mut self,
        identity_hex: &str,
        peer_name: &str,
        epoch: u64,
        data: &PreKeyBundleData,
    ) -> SessionResult<bool> {
        let rotated = self.bind_contact_key_epoch(identity_hex, peer_name, epoch)?;
        self.ensure_address_live(peer_name)?;
        self.init_session(peer_name, data)?;
        Ok(rotated)
    }

    // ---- Persistence (v6, RT-26.1) --------------------------------------
    //
    // Полное состояние менеджера в одном CBOR-блобе. Вызывающая сторона
    // (FFI/iOS) обязана шифровать его в покое (min_storage под storage key):
    // snapshot содержит identity private key и все session keys.

    /// Сериализует всё состояние менеджера И аутентицирует его keyed-MAC'ом
    /// от внешнего ключа (RT-26.1 finding: подмена байта в неаутентифицированном
    /// блобе проходила — CBOR-парсер терпим к мутациям хвостовых полей).
    /// `mac_key` — 32 байта, выводимые вызывающим из storage key (НЕ равный ему
    /// желательно: BLAKE3-derive). Возвращает `CBOR || tag[32]`.
    ///
    /// SECURITY: блоб содержит identity private key и все session keys —
    /// вызывающая сторона обязана дополнительно шифровать его в покое.
    pub fn snapshot(&self, mac_key: &[u8; 32]) -> SessionResult<Vec<u8>> {
        let identity_pair = block_on(async {
            IdentityKeyStore::get_identity_key_pair(&self.store.identity_store).await
        })
        .map_err(|e| crate::SessionError::Crypto(e.to_string()))?
        .serialize()
        .to_vec();
        let registration_id = self.registration_id();

        let mut peer_snaps = Vec::new();
        for name in &self.peers {
            let addr = address_of(name);
            let record = block_on(async {
                SessionStore::load_session(&self.store.session_store, &addr).await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            let session_record = match record {
                Some(r) => Some(
                    r.serialize()
                        .map_err(|e| crate::SessionError::Crypto(e.to_string()))?,
                ),
                None => None,
            };
            let identity_key = block_on(async {
                IdentityKeyStore::get_identity(&self.store.identity_store, &addr).await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?
            .map(|ik| ik.serialize().to_vec());
            peer_snaps.push(PeerSnapshot {
                name: name.clone(),
                identity_key,
                session_record,
                guard: self.guards.get(name).cloned(),
            });
        }

        let mut one_time_pre_keys = Vec::new();
        for id in self.store.all_pre_key_ids() {
            let id = *id;
            let rec =
                block_on(async { PreKeyStore::get_pre_key(&self.store.pre_key_store, id).await })
                    .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            let bytes = rec
                .serialize()
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            one_time_pre_keys.push((u32::from(id), bytes));
        }

        let mut signed_pre_keys = Vec::new();
        for id in self.store.all_signed_pre_key_ids() {
            let id = *id;
            let rec = block_on(async {
                SignedPreKeyStore::get_signed_pre_key(&self.store.signed_pre_key_store, id).await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            let bytes = rec
                .serialize()
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            signed_pre_keys.push((u32::from(id), bytes));
        }

        let mut kyber_pre_keys = Vec::new();
        for id in self.store.all_kyber_pre_key_ids() {
            let id = *id;
            let rec = block_on(async {
                KyberPreKeyStore::get_kyber_pre_key(&self.store.kyber_pre_key_store, id).await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            let bytes = rec
                .serialize()
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            kyber_pre_keys.push((u32::from(id), bytes));
        }

        let snap = SessionSnapshot {
            format: SNAPSHOT_FORMAT,
            local_name: self.local_name.clone(),
            identity_pair,
            registration_id,
            peers: peer_snaps,
            one_time_pre_keys,
            signed_pre_keys,
            kyber_pre_keys,
            peer_epochs: self
                .peer_epochs
                .iter()
                .map(|(id, (peer, e))| (id.clone(), peer.clone(), *e))
                .collect(),
            stale_addresses: self.stale_addresses.iter().cloned().collect(),
            identity_fingerprint: Some(identity_fingerprint(&self.identity_key_public()).to_vec()),
        };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&snap, &mut out)
            .map_err(|e| crate::SessionError::Crypto(format!("snapshot encode: {e}")))?;
        // Аутентификация: BLAKE3-keyed MAC по CBOR-байтам + домен.
        let tag = blake3::keyed_hash(
            mac_key,
            &[out.as_slice(), b"min-session-snapshot/v1"].concat(),
        );
        out.extend_from_slice(tag.as_bytes());
        Ok(out)
    }
}

/// Формат snapshot'а (RT-26.1). Расширять только вперёд-совместимо.
const SNAPSHOT_FORMAT: u32 = 1;

/// Состояние одного пира в snapshot'е.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PeerSnapshot {
    name: String,
    identity_key: Option<Vec<u8>>,
    session_record: Option<Vec<u8>>,
    guard: Option<PeerGuard>,
}

/// Полное сериализуемое состояние SessionManager.
///
/// SECURITY: содержит identity private key и все session/pre keys —
/// вызывающая сторона обязана шифровать блоб в покое (min-storage).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SessionSnapshot {
    format: u32,
    local_name: String,
    identity_pair: Vec<u8>,
    registration_id: u32,
    peers: Vec<PeerSnapshot>,
    one_time_pre_keys: Vec<(u32, Vec<u8>)>,
    signed_pre_keys: Vec<(u32, Vec<u8>)>,
    kyber_pre_keys: Vec<(u32, Vec<u8>)>,
    /// RT-26.2: отпечаток identity владельца (blake3-derive от identity_pub,
    /// 16 байт). Внутри MACed-блоба → tamper невозможен; используется
    /// `restore_checked` для отказа при restore отозванного устройства.
    #[serde(default)]
    identity_fingerprint: Option<Vec<u8>>,
    /// MIN-26: (identity_hex, peer_address, epoch) — привязка адреса к эпохе.
    #[serde(default)]
    peer_epochs: Vec<(String, String, u64)>,
    /// MIN-26: адреса эпох, закрытых ротацией.
    #[serde(default)]
    stale_addresses: Vec<String>,
}

/// RT-26.2: отпечаток identity — привязка snapshot'а к владельцу.
/// Домен отделён (derive_key), 16 байт — совместимо с min-device device_id.
fn identity_fingerprint(identity_public: &[u8]) -> [u8; 16] {
    let digest = blake3::derive_key("min-session-identity-fp/v1", identity_public);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

impl SessionManager {
    /// Восстанавливает менеджер из аутентифицированного snapshot'а
    /// (`CBOR || tag[32]`, см. `snapshot`). Неверный MAC / тампер / мусор /
    /// чужой `mac_key` → отказ до любой десериализации (fail-closed).
    /// `local_name` обязан совпадать с сохранённым: PQ-ratchet привязывает
    /// состояние к паре адресов (remote, local).
    pub fn restore(local_name: &str, blob: &[u8], mac_key: &[u8; 32]) -> SessionResult<Self> {
        Self::restore_inner(local_name, blob, mac_key).map(|(mgr, _)| mgr)
    }

    /// RT-26.2: restore с проверкой отзыва устройства. `revoked_fingerprints`
    /// — список отпечатков (16 Б, домен `min-session-identity-fp/v1`), которые
    /// приложение считает отозванными (полученные revoke-сертификаты).
    /// Snapshot отозванного identity → `RevokedIdentity` (rollback/реставрация
    /// отозванного ключа через старый бэкап невозможна).
    pub fn restore_checked(
        local_name: &str,
        blob: &[u8],
        mac_key: &[u8; 32],
        revoked_fingerprints: &[[u8; 16]],
    ) -> SessionResult<Self> {
        let (mgr, snap_fp) = Self::restore_inner(local_name, blob, mac_key)?;
        if let Some(fp) = snap_fp {
            let fp: [u8; 16] = fp.as_slice().try_into().map_err(|_| {
                crate::SessionError::Crypto("snapshot identity_fingerprint length".to_owned())
            })?;
            if revoked_fingerprints.contains(&fp) {
                return Err(crate::SessionError::RevokedIdentity);
            }
        }
        Ok(mgr)
    }

    fn restore_inner(
        local_name: &str,
        blob: &[u8],
        mac_key: &[u8; 32],
    ) -> SessionResult<(Self, Option<Vec<u8>>)> {
        if blob.len() < 32 {
            return Err(crate::SessionError::Crypto("snapshot too short".to_owned()));
        }
        let (body, tag_bytes) = blob.split_at(blob.len() - 32);
        let expected = blake3::keyed_hash(
            mac_key,
            &[body, b"min-session-snapshot/v1".as_slice()].concat(),
        );
        use subtle::ConstantTimeEq;
        if expected.as_bytes().ct_eq(tag_bytes).unwrap_u8() != 1 {
            return Err(crate::SessionError::Crypto(
                "snapshot MAC mismatch".to_owned(),
            ));
        }

        let snap: SessionSnapshot = ciborium::de::from_reader(body)
            .map_err(|e| crate::SessionError::Crypto(format!("snapshot decode: {e}")))?;
        if snap.format != SNAPSHOT_FORMAT {
            return Err(crate::SessionError::Crypto(format!(
                "unsupported snapshot format: {}",
                snap.format
            )));
        }
        if snap.local_name != local_name {
            return Err(crate::SessionError::Crypto(
                "snapshot local_name mismatch (PQ-ratchet address binding)".to_owned(),
            ));
        }
        let snap_fp = snap.identity_fingerprint.clone();

        let identity_pair = IdentityKeyPair::try_from(snap.identity_pair.as_slice())
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        let store = InMemSignalProtocolStore::new(identity_pair, snap.registration_id)
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        let mut mgr = Self {
            store,
            local_name: local_name.to_owned(),
            peers: std::collections::BTreeSet::new(),
            guards: std::collections::HashMap::new(),
            peer_epochs: std::collections::BTreeMap::new(),
            stale_addresses: std::collections::BTreeSet::new(),
        };

        for p in snap.peers {
            let addr = address_of(&p.name);
            if let Some(rec_bytes) = p.session_record {
                let record = SessionRecord::deserialize(&rec_bytes)
                    .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
                block_on(async {
                    SessionStore::store_session(&mut mgr.store.session_store, &addr, &record).await
                })
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            }
            if let Some(ik_bytes) = p.identity_key {
                let ik = IdentityKey::try_from(ik_bytes.as_slice())
                    .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
                block_on(async {
                    IdentityKeyStore::save_identity(&mut mgr.store.identity_store, &addr, &ik).await
                })
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            }
            if let Some(guard) = p.guard {
                mgr.guards.insert(p.name.clone(), guard);
            }
            mgr.peers.insert(p.name);
        }
        // MIN-26: состояние эпох восстанавливается вместе с MACed-блобом —
        // откат бэкапа не «оживляет» адреса ротированных эпох.
        mgr.peer_epochs = snap
            .peer_epochs
            .into_iter()
            .map(|(id, p, e)| (id, (p, e)))
            .collect();
        mgr.stale_addresses = snap.stale_addresses.into_iter().collect();

        for (id, bytes) in snap.one_time_pre_keys {
            let rec = PreKeyRecord::deserialize(&bytes)
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            block_on(async {
                PreKeyStore::save_pre_key(&mut mgr.store.pre_key_store, PreKeyId::from(id), &rec)
                    .await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        }
        for (id, bytes) in snap.signed_pre_keys {
            let rec = SignedPreKeyRecord::deserialize(&bytes)
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            block_on(async {
                SignedPreKeyStore::save_signed_pre_key(
                    &mut mgr.store.signed_pre_key_store,
                    SignedPreKeyId::from(id),
                    &rec,
                )
                .await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        }
        for (id, bytes) in snap.kyber_pre_keys {
            let rec = KyberPreKeyRecord::deserialize(&bytes)
                .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
            block_on(async {
                KyberPreKeyStore::save_kyber_pre_key(
                    &mut mgr.store.kyber_pre_key_store,
                    KyberPreKeyId::from(id),
                    &rec,
                )
                .await
            })
            .map_err(|e| crate::SessionError::Crypto(e.to_string()))?;
        }

        Ok((mgr, snap_fp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_type_of(ciphertext: &[u8]) -> &'static str {
        match ciphertext[0] {
            0x01 => "prekey",
            0x02 => "whisper",
            _ => "unknown",
        }
    }

    #[test]
    fn manager_creation() {
        let sm = SessionManager::new("alice").unwrap();
        assert_eq!(sm.identity_key_public().len(), 33); // 0x05 prefix + 32 bytes
        assert!(sm.registration_id() > 0);
        assert!(sm.registration_id() <= 0x3FFF);
    }

    #[test]
    fn prekey_bundle_generation() {
        let mut sm = SessionManager::new("bob").unwrap();
        let bundle = sm.generate_prekey_bundle().unwrap();
        assert_eq!(bundle.identity_key.len(), 33);
        assert_eq!(bundle.pre_key_public.len(), 33);
        assert_eq!(bundle.signed_pre_key_public.len(), 33);
        assert_eq!(bundle.signed_pre_key_signature.len(), 64);
        // Kyber-1024 public key: 1568 bytes + 1 type-prefix byte.
        assert_eq!(bundle.kyber_pre_key_public.len(), 1569);
        assert!(!bundle.kyber_pre_key_signature.is_empty());
    }

    #[test]
    fn bundle_cbor_roundtrip() {
        let mut sm = SessionManager::new("bob").unwrap();
        let bundle = sm.generate_prekey_bundle().unwrap();

        let cbor = bundle.to_cbor().unwrap();
        assert!(!cbor.is_empty());

        let back = PreKeyBundleData::from_cbor(&cbor).unwrap();
        assert_eq!(back, bundle);

        // Determinism: two encodings of the same value are byte-identical.
        let cbor2 = bundle.to_cbor().unwrap();
        assert_eq!(cbor, cbor2);

        // Trailing garbage is rejected (strict parsing policy).
        let mut garbage = cbor.clone();
        garbage.push(0xFF);
        assert!(PreKeyBundleData::from_cbor(&garbage).is_err());

        // Empty input rejected.
        assert!(PreKeyBundleData::from_cbor(&[]).is_err());

        // Oversized untrusted input is rejected before CBOR allocation.
        assert!(PreKeyBundleData::from_cbor(&vec![0u8; MAX_PREKEY_BUNDLE_CBOR + 1]).is_err());
    }

    #[test]
    fn bundle_cbor_rejects_unknown_fields() {
        use ciborium::value::Value;
        let mut sm = SessionManager::new("bob").unwrap();
        let bundle = sm.generate_prekey_bundle().unwrap();
        let bytes = bundle.to_cbor().unwrap();
        let mut value: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(ref mut fields) = value else {
            panic!("bundle must encode as map")
        };
        fields.push((
            Value::Text("unknown_field".into()),
            Value::Integer(1.into()),
        ));
        let mut unknown = Vec::new();
        ciborium::ser::into_writer(&value, &mut unknown).unwrap();
        assert!(PreKeyBundleData::from_cbor(&unknown).is_err());
    }

    #[test]
    fn pqxdh_full_cycle() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();

        let bob_bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bob_bundle).unwrap();

        // First message MUST be a PreKeySignalMessage (session initiation).
        let pt1 = b"L'homme est condamne a etre libre";
        let ct1 = alice.encrypt("bob", pt1).unwrap();
        assert_eq!(msg_type_of(&ct1), "prekey");

        // Bob processes it — session established on his side.
        let recovered = bob.decrypt("alice", &ct1).unwrap();
        assert_eq!(recovered, pt1.to_vec());

        // Bob replies: now a Whisper message (Double Ratchet, no prekey).
        let pt2 = b"Who watches the watchers?";
        let ct2 = bob.encrypt("alice", pt2).unwrap();
        assert_eq!(msg_type_of(&ct2), "whisper");
        let recovered2 = alice.decrypt("bob", &ct2).unwrap();
        assert_eq!(recovered2, pt2.to_vec());
    }

    #[test]
    fn double_ratchet_many_messages() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bob_bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bob_bundle).unwrap();

        let mut ciphertexts = Vec::new();
        for i in 0..10 {
            let pt = format!("msg {i}");
            let ct = alice.encrypt("bob", pt.as_bytes()).unwrap();
            assert_ne!(ct, pt.as_bytes().to_vec());
            ciphertexts.push(ct);
        }

        for (i, ct) in ciphertexts.iter().enumerate() {
            let pt = format!("msg {i}");
            assert_eq!(bob.decrypt("alice", ct).unwrap(), pt.as_bytes().to_vec());
        }

        let ct_back = bob.encrypt("alice", b"reply").unwrap();
        assert_eq!(alice.decrypt("bob", &ct_back).unwrap(), b"reply".to_vec());
    }

    #[test]
    fn out_of_order_reception() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bob_bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bob_bundle).unwrap();

        // Warm up: first message is the prekey one.
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();

        // Send three, deliver out of order: 2, 0, 1.
        let cts: Vec<Vec<u8>> = (0..3)
            .map(|i| alice.encrypt("bob", format!("m{i}").as_bytes()).unwrap())
            .collect();
        assert_eq!(bob.decrypt("alice", &cts[2]).unwrap(), b"m2".to_vec());
        assert_eq!(bob.decrypt("alice", &cts[0]).unwrap(), b"m0".to_vec());
        assert_eq!(bob.decrypt("alice", &cts[1]).unwrap(), b"m1".to_vec());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bob_bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bob_bundle).unwrap();

        let ct = alice.encrypt("bob", b"secret").unwrap();

        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(bob.decrypt("alice", &tampered).is_err());
    }

    #[test]
    fn forged_identity_bundle_rejected() {
        // Mallory cannot substitute her identity into Bob's bundle:
        // the signed-prekey / kyber signature check must fail.
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let mut mallory = SessionManager::new("mallory").unwrap();

        let bob_bundle = bob.generate_prekey_bundle().unwrap();
        let mallory_bundle = mallory.generate_prekey_bundle().unwrap();

        let mut forged = bob_bundle.clone();
        forged.identity_key = mallory_bundle.identity_key;
        forged.signed_pre_key_signature = mallory_bundle.signed_pre_key_signature;
        forged.kyber_pre_key_signature = mallory_bundle.kyber_pre_key_signature;

        assert!(
            alice.init_session("bob", &forged).is_err(),
            "forged bundle must be rejected"
        );
    }

    /// AUDIT RT-2 (PROTOCOL §73): skipped-key cap = 100.
    /// Гэп ratchet-counter'ов ≥ 100 → SkippedKeyLimitExceeded, а не
    /// бесшовное создание 100+ skipped keys (бесконечный ретрай-цикл
    /// и разрастание памяти).
    #[test]
    fn skipped_key_cap_rejects_large_gap() {
        let (mut bob, mut alice) = fresh_pair();

        // Warm-up: первое сообщение — prekey, ratchet устанавливается.
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();

        // 120 сообщений; доставляем только последнее (counter 120,
        // ожидаемый базовый counter у Боба = 1 → гэп 119 ≥ 100).
        let cts: Vec<Vec<u8>> = (0..120)
            .map(|i| alice.encrypt("bob", format!("m{i}").as_bytes()).unwrap())
            .collect();
        assert!(
            matches!(
                bob.decrypt("alice", &cts[119]),
                Err(crate::SessionError::SkippedKeyLimitExceeded)
            ),
            "large gap must be capped, got {:?}",
            bob.decrypt("alice", &cts[119])
                .map(|_| "OK(!)")
                .map_err(|e| e.to_string())
        );
        assert_eq!(
            bob.guard_resyncs("alice"),
            1,
            "cap must resync the base once"
        );

        // MIN-18 (anti-DoS): сессия НЕ забрикена. Повторное прибытие того же
        // сообщения после пересинхронизации базы имеет гэп 0 и принимается
        // (skipped-key storage при отказе не тратился).
        assert_eq!(bob.decrypt("alice", &cts[119]).unwrap(), b"m119");

        // Anti-replay на ratchet-уровне: точный дубликат уже принятого
        // сообщения отклоняется (DuplicatedMessage). Доставка «пропущенного»
        // ранее сообщения — легитимный skipped-key путь, его отсекает
        // envelope-seq (PROTOCOL §4: монотонный seq per session+direction).
        assert!(
            bob.decrypt("alice", &cts[119]).is_err(),
            "exact duplicate must be rejected"
        );
    }

    // AUDIT v4: ad-hoc диагностики `tamper_byte_scan_diagnostic` и
    // `prekey_fresh_scan_diagnostic` консолидированы. Постоянное покрытие —
    // `whisper_byte_tamper_scan_rejected` (сессионный слой) и
    // `prekey_envelope_ciphertext_tamper_rejected` (envelope-слой, MIN-19):
    // Kyber-хвост PreKey-конверта не аутентифицирован внутренним MAC libsignal,
    // его целостность обеспечивает commitment (MIN-17), а не сессия.

    /// AUDIT RT-3 (фаза T, постоянный тест): строгий байт-скан whisper-сообщения.
    /// Мутируем КАЖДЫЙ из 122 байт на свежей паре (сессия + handshake), чтобы
    /// исключить артефакты ratchet-состояния от предыдущих попыток. Ни один байт
    /// не должен приниматься — иначе нашлось бы поле, не покрытое MAC libsignal.
    /// Запускается в CI (debug ≈ 2 с).
    #[test]
    fn rt3_whisper_tamper_sweep_rejected() {
        let started = std::time::Instant::now();
        let len = {
            let (mut bob, mut alice) = fresh_pair();
            let init_ct = alice.encrypt("bob", b"init").unwrap();
            bob.decrypt("alice", &init_ct).unwrap();
            let ack = bob.encrypt("alice", b"ack").unwrap();
            alice.decrypt("bob", &ack).unwrap();
            let probe = alice.encrypt("bob", b"AAAAAAAAAAAAAAAAAAAA").unwrap();
            assert_eq!(probe[0], 0x02, "expected whisper after handshake");
            probe.len()
        };
        println!("whisper ct len = {len}");
        let mut accepted: Vec<usize> = Vec::new();
        for pos in 0..len {
            let (mut bob, mut alice) = fresh_pair();
            // Handshake: prekey → ack (чтобы обе стороны имели сессию).
            let init_ct = alice.encrypt("bob", b"init").unwrap();
            bob.decrypt("alice", &init_ct).unwrap();
            let ack = bob.encrypt("alice", b"ack").unwrap();
            alice.decrypt("bob", &ack).unwrap();

            let mut ct = alice.encrypt("bob", b"AAAAAAAAAAAAAAAAAAAA").unwrap();
            assert_eq!(ct[0], 0x02, "expected whisper, got {:#x}", ct[0]);
            ct[pos] ^= 0xFF;
            if let Ok(pt) = bob.decrypt("alice", &ct) {
                accepted.push(pos);
                println!("ACCEPTED byte {pos:4}: {:?}", String::from_utf8_lossy(&pt));
            }
        }
        println!(
            "whisper fresh-session accepted positions: {accepted:?} (elapsed {:?})",
            started.elapsed()
        );
        assert!(
            accepted.is_empty(),
            "unauthenticated whisper bytes: {accepted:?}"
        );
    }

    /// Red-team MIN-18: принудительный DoS через дроп сообщений.
    /// Relay дропает 150 whisper-сообщений, затем доставляет 151-е.
    /// Если precheck навсегда блокирует сессию (next_counter застрял) —
    /// это атака на доступность.
    #[test]
    fn dropped_messages_do_not_brick_session() {
        let (mut bob, mut alice) = fresh_pair();
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();
        let ack = bob.encrypt("alice", b"ack").unwrap();
        alice.decrypt("bob", &ack).unwrap();

        // Relay дропает 150 сообщений (не доставляет их Бобу).
        for i in 0..150 {
            let _ = alice
                .encrypt("bob", format!("dropped{i}").as_bytes())
                .unwrap();
        }

        // 151-е приходит Бобу: либо расшифровка, либо один отказ с resync.
        let m = alice.encrypt("bob", b"survivor").unwrap();
        let first = bob.decrypt("alice", &m);
        println!(
            "after 150 dropped: first attempt = {:?}",
            first.as_ref().map(|_| "OK").map_err(|e| e.to_string())
        );

        // Ключевое: ПОСЛЕДУЮЩИЕ сообщения обязаны приниматься.
        let mut recovered = false;
        for i in 0..5 {
            let n = alice.encrypt("bob", format!("next{i}").as_bytes()).unwrap();
            match bob.decrypt("alice", &n) {
                Ok(pt) => {
                    println!("next{i} OK: {:?}", String::from_utf8_lossy(&pt));
                    recovered = true;
                    break;
                }
                Err(e) => println!("next{i} Err: {e}"),
            }
        }
        assert!(
            recovered,
            "MIN-18: session permanently bricked by dropped messages (DoS)"
        );
    }

    /// Свежая пара (bob, alice) без установленного ratchet-состояния.
    #[cfg(test)]
    fn fresh_pair() -> (SessionManager, SessionManager) {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        (bob, alice)
    }

    /// Красная команда: переживает ли установленная сессия инъекцию мусорных
    /// PreKey-сообщений (DoS через перезапись session record)? Ответ: да,
    /// сессия выживает — бесплатного «сломать собеседника» не существует.
    /// AUDIT MIN-22: тест был диагностикой с тавтологичным assert
    /// (`x == false || true`), который не мог упасть и маскировал регрессии.
    /// Теперь — постоянный тест с реальными проверками.
    #[test]
    fn junk_prekey_injection_does_not_brick_session() {
        let (mut bob, mut alice) = handshaken_pair();

        // Работающая сессия: честное whisper проходит.
        let ok1 = alice.encrypt("bob", b"before-junk").unwrap();
        assert_eq!(bob.decrypt("alice", &ok1).unwrap(), b"before-junk");

        // Инъекция 5 испорченных PreKey/whisper-сообщений (как это сделал бы relay).
        for i in 0..5 {
            let mut junk = alice.encrypt("bob", b"junk").unwrap();
            let last = junk.len() - 1;
            junk[last] ^= 0xFF;
            bob.reset_guards();
            assert!(
                bob.decrypt("alice", &junk).is_err(),
                "junk #{i} must be rejected (no plaintext oracle)"
            );
        }

        // Сессия обязана остаться рабочей: ни перезаписи session record,
        // ни залипания в SUSPICIOUS.
        let ok2 = alice.encrypt("bob", b"after-junk").unwrap();
        assert_eq!(
            bob.decrypt("alice", &ok2).unwrap(),
            b"after-junk",
            "established session must survive junk injection (no DoS)"
        );
        assert!(
            !bob.is_suspicious("alice"),
            "session must not stay SUSPICIOUS after honest traffic"
        );
    }

    /// Красная команда MIN-19/RT-3 (PoC): мутация Kyber-части PreKey-конверта
    /// (по сканам — 1569 из 1788 байт не покрыты MAC libsignal) детектируется
    /// на уровне envelope-commitment (MIN-17), ДО криптообработки.
    #[test]
    fn prekey_envelope_ciphertext_tamper_rejected() {
        use min_protocol::envelope::{EnvelopeV1, MessageType};

        let (_bob, mut alice) = fresh_pair();
        let ct = alice.encrypt("bob", b"AAAA").unwrap();
        assert_eq!(ct[0], 0x01, "expected prekey message");
        assert!(
            ct.len() > 219,
            "kyber area must be present (len={})",
            ct.len()
        );

        let session_id = b"prekey-envelope-binding";
        let mut env = EnvelopeV1 {
            msg_type: MessageType::Message,
            epoch: 1,
            seq: 1,
            sender_hint: [0u8; 16],
            mailbox_hint: [0u8; 16],
            aad_commitment: [0u8; 16],
            nonce: [7u8; 24],
            ciphertext: ct,
            ttl_sec: 600,
            queue_class: 0,
        };
        env.seal(session_id);
        let wire = env.to_wire().unwrap();
        assert!(EnvelopeV1::from_wire_verified(&wire, session_id).is_ok());

        // Позиция 219 из байт-скана — внутри Kyber-шифротекста.
        let mut fake = env.clone();
        fake.ciphertext[219] ^= 0xFF;
        fake.aad_commitment = env.aad_commitment; // старый commitment, байт подменён
        let tampered = fake.to_wire().unwrap();
        assert_eq!(
            EnvelopeV1::from_wire_verified(&tampered, session_id).unwrap_err(),
            min_protocol::ProtocolError::CommitmentMismatch,
            "kyber-часть prekey обязана быть связана commitment'ом (MIN-17/19)"
        );
    }
    /// AUDIT RT-3f (PROTOCOL §73): 3 неудачные расшифровки подряд →
    /// SUSPICIOUS (остывание): последующие расшифровки временно
    /// отклоняются, бесконечный decrypt-oracle невозможен.
    #[test]
    fn three_failures_trigger_cooling() {
        let (mut bob, mut alice) = fresh_pair();

        // Устанавливаем сессию и делаем ack, чтобы сообщения стали whisper
        // (0x02). Тампер PreKey-конверта НЕ детектируется (MIN-19 —
        // malleability последних байтов в libsignal), поэтому проверяем
        // остывание на whisper-сообщениях, где MAC покрывает каждый байт.
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();
        let ack = bob.encrypt("alice", b"ack").unwrap();
        alice.decrypt("bob", &ack).unwrap();

        // Три тамперированных whisper-сообщения → три неудачных расшифровки.
        for i in 0..3 {
            let mut ct = alice
                .encrypt("bob", format!("legit{i}").as_bytes())
                .unwrap();
            assert_eq!(ct[0], 0x02, "expected whisper after ack");
            let last = ct.len() - 1;
            ct[last] ^= 0xFF;
            let r = bob.decrypt("alice", &ct);
            assert!(
                r.is_err(),
                "tampered must fail, got {:?}",
                r.map(|_| "OK(!)")
            );
        }
        assert!(bob.is_suspicious("alice"), "3 fails must trigger cooling");

        // Четвёртое — даже честное — отклоняется на время остывания.
        let honest = alice.encrypt("bob", b"legit3").unwrap();
        assert!(
            bob.decrypt("alice", &honest).is_err(),
            "honest message must be rejected while cooling"
        );
    }

    /// AUDIT RT-1: replay того же ciphertext (relay дублирует envelope).
    /// Ожидание: повторная доставка отвергается (libsignal DuplicatedMessage),
    /// plaintext не выдаётся дважды.
    #[test]
    fn rt1_replay_is_rejected() {
        let (mut bob, mut alice) = fresh_pair();
        let ct = alice.encrypt("bob", b"replay-me").unwrap();

        // Первая доставка — честная.
        assert_eq!(bob.decrypt("alice", &ct).unwrap(), b"replay-me");
        // Повтор той же байтовой строки — дроп (не второй plaintext).
        let replay = bob.decrypt("alice", &ct);
        assert!(
            replay.is_err(),
            "replayed ciphertext must be rejected, got {:?}",
            replay.map(|p| String::from_utf8_lossy(&p).to_string())
        );
    }

    /// AUDIT RT-4: truncation — обрезка ciphertext не должна приводить к панике
    /// и не должна расшифровываться.
    #[test]
    fn rt4_truncated_ciphertext_rejected() {
        let (mut bob, mut alice) = fresh_pair();
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();
        let ack = bob.encrypt("alice", b"ack").unwrap();
        alice.decrypt("bob", &ack).unwrap();

        let ct = alice.encrypt("bob", b"truncate-me").unwrap();
        for cut in [1usize, 8, 16, ct.len() / 2, ct.len() - 1] {
            let truncated = &ct[..ct.len().saturating_sub(cut).max(1)];
            let r = bob.decrypt("alice", truncated);
            assert!(r.is_err(), "truncated by {cut} bytes must not decrypt");
            bob.reset_guards();
        }
    }

    /// AUDIT RT-5: reflect/echo — собственный ciphertext, отданный себе,
    /// не расшифровывается (identity binding, не «сам с собой» сессия).
    #[test]
    fn rt5_reflected_message_rejected() {
        let mut alice = SessionManager::new("alice").unwrap();
        let mut bob = SessionManager::new("bob").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();

        let ct = alice.encrypt("bob", b"echo").unwrap();
        // Эхо возвращается Алисе как если бы пришло от Боба.
        assert!(
            alice.decrypt("bob", &ct).is_err(),
            "reflected own ciphertext must not decrypt"
        );
    }

    /// AUDIT RT-2/MIN-18: пропуск сообщений (потерянные пакеты) не должен
    /// «заклинивать» сессию навсегда, но и не должен позволять бесконечный
    /// гэп: кап срабатывает, база пересинхронизируется, телеметрия растёт.
    #[test]
    fn rt2_loss_and_gap_cap_are_bounded() {
        let (mut bob, mut alice) = fresh_pair();

        // Потеря 30 сообщений подряд (в пределах капа) — сессия обязана
        // продолжать работать, а не «заклинить».
        let mut delivered = 0;
        for i in 0..30 {
            let ct = alice.encrypt("bob", format!("lost{i}").as_bytes()).unwrap();
            if bob.decrypt("alice", &ct).is_err() {
                bob.reset_guards();
            } else {
                delivered += 1;
            }
        }
        assert!(delivered > 0, "session must keep working through losses");
        assert_eq!(
            bob.guard_resyncs("alice"),
            0,
            "in-cap losses must not resync"
        );
    }

    /// Помощник: пара с ЗАВЕРШЁННЫМ рукопожатием (init доставлен, ack получен),
    /// т.е. Alice шифрует whisper-сообщениями (0x02).
    fn handshaken_pair() -> (SessionManager, SessionManager) {
        let (mut bob, mut alice) = fresh_pair();
        let init = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init).unwrap();
        let ack = bob.encrypt("alice", b"ack").unwrap();
        alice.decrypt("bob", &ack).unwrap();
        (bob, alice)
    }

    /// Помощник: принял ли Боб тамперированный ciphertext (с чистыми guards).
    fn accepted_by_bob(bob: &mut SessionManager, ct: &[u8]) -> bool {
        bob.reset_guards();
        bob.decrypt("alice", ct).is_ok()
    }

    /// HARNESS (не в CI): байт-карта PreKey-конверта libsignal.
    ///
    /// Запуск: `cargo test -p min-session -- --ignored --nocapture
    /// harness_libsignal_prekey_bytemap`
    ///
    /// Зачем: фиксирует доказательство к MIN-19. На установленной сессии
    /// libsignal берёт сессию из ВНЕШНИХ полей конверта и расшифровывает
    /// внутренний whisper; при этом ~1569 из 1788 позиций (Kyber-шифротекст
    /// ML-KEM-1024 = 1568 Б) мутируются без отказа — PQ-часть не покрыта
    /// собственным MAC libsignal. У MIN целостность даёт envelope-commitment
    /// (MIN-17), проверяемый ДО криптообработки (см. постоянный тест
    /// `prekey_envelope_ciphertext_tamper_rejected`).
    ///
    /// Ценность harness'а: при следующем bump'е libsignal (MIN-16) прогнать
    /// заново и увидеть, стала ли PQ-часть аутентифицированной (accepted → 0).
    #[test]
    #[ignore = "harness: libsignal prekey bytemap evidence (MIN-19)"]
    fn harness_libsignal_prekey_bytemap() {
        let started = std::time::Instant::now();
        let len = {
            let (mut bob, mut alice) = fresh_pair();
            let init = alice.encrypt("bob", b"init").unwrap();
            bob.decrypt("alice", &init).unwrap();
            alice.encrypt("bob", b"AAAAAAAAAAAAAAAAAAAA").unwrap().len()
        };
        println!("established prekey msg len = {len}");
        let mut accepted: Vec<usize> = Vec::new();
        for pos in 0..len {
            let (mut bob, mut alice) = fresh_pair();
            let init = alice.encrypt("bob", b"init").unwrap();
            bob.decrypt("alice", &init).unwrap();
            let mut ct = alice.encrypt("bob", b"AAAAAAAAAAAAAAAAAAAA").unwrap();
            ct[pos] ^= 0xFF;
            if accepted_by_bob(&mut bob, &ct) {
                accepted.push(pos);
            }
        }
        println!(
            "established-prekey accepted positions ({}): {accepted:?} (elapsed {:?})",
            accepted.len(),
            started.elapsed()
        );
    }

    /// HARNESS (не в CI): байт-карта whisper-сообщения на УСТАНОВЛЕННОЙ сессии.
    ///
    /// Запуск: `cargo test -p min-session -- --ignored --nocapture
    /// harness_libsignal_whisper_bytemap`
    ///
    /// Отличие от постоянного `rt3_whisper_tamper_sweep_rejected`: там скан идёт
    /// на свежесозданной сессии, здесь — на сессии с завершённым рукопожатием и
    /// сброшенными guard'ами (обход cooling), т.е. проверяется именно MAC
    /// libsignal, без влияния анти-abuse-логики MIN. Печатает карту позиций.
    #[test]
    #[ignore = "harness: libsignal whisper bytemap evidence (established session)"]
    fn harness_libsignal_whisper_bytemap() {
        let started = std::time::Instant::now();
        let len = {
            let (mut bob, mut alice) = handshaken_pair();
            let probe = alice.encrypt("bob", b"AAAAAAAAAAAAAAAAAAAA").unwrap();
            assert_eq!(probe[0], 0x02);
            let _ = &mut bob;
            probe.len()
        };
        println!("whisper msg len = {len}");
        let mut accepted: Vec<usize> = Vec::new();
        for pos in 0..len {
            let (mut bob, mut alice) = handshaken_pair();
            let mut ct = alice.encrypt("bob", b"AAAAAAAAAAAAAAAAAAAA").unwrap();
            ct[pos] ^= 0xFF;
            if accepted_by_bob(&mut bob, &ct) {
                accepted.push(pos);
            }
        }
        println!(
            "whisper accepted positions ({}): {accepted:?} (elapsed {:?})",
            accepted.len(),
            started.elapsed()
        );
        assert!(
            accepted.is_empty(),
            "unauthenticated whisper bytes: {accepted:?}"
        );
    }

    /// Persistence (v6, RT-26.1): полный roundtrip — сессия восстанавливается
    /// из snapshot'а и продолжает расшифровывать новые сообщения.
    #[test]
    fn snapshot_roundtrip_preserves_session() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();

        let mk = test_mac_key();
        let snap = bob.snapshot(&mk).unwrap();
        let mut bob2 = SessionManager::restore("bob", &snap, &mk).unwrap();

        // Новое сообщение после «рестарта» расшифровывается.
        let next = alice.encrypt("bob", b"after-restore").unwrap();
        let pt = bob2.decrypt("alice", &next).unwrap();
        assert_eq!(pt, b"after-restore");
    }

    /// Вывод MAC-ключа snapshot'а из storage key (как будет делать FFI-слой).
    fn test_mac_key() -> [u8; 32] {
        blake3::derive_key("min-session-snapshot-key/v1", b"test-storage-key")
    }

    /// Persistence (v6, RT-26.1): tampered snapshot отклоняется (fail-closed).
    /// Найдено в v6: неаутентицированный блоб принимал мутации байтов —
    /// фикс: keyed MAC; тампер CBOR-части И тампер тега детектируются;
    /// чужой mac_key и мусорный вход — тоже.
    #[test]
    fn restore_rejects_tampered_or_garbage_snapshot() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        bob.decrypt("alice", &alice.encrypt("bob", b"init").unwrap())
            .unwrap();

        let mk = test_mac_key();
        let mut snap = bob.snapshot(&mk).unwrap();

        // Тампер байта внутри CBOR-тела.
        let mut tampered = snap.clone();
        tampered[10] ^= 0x01;
        assert!(SessionManager::restore("bob", &tampered, &mk).is_err());

        // Тампер байта тега (последние 32).
        let last = snap.len() - 1;
        snap[last] ^= 0x01;
        assert!(SessionManager::restore("bob", &snap, &mk).is_err());

        // Чужой mac_key → отказ.
        let snap_ok = bob.snapshot(&mk).unwrap();
        let wrong_key = [0u8; 32];
        assert!(SessionManager::restore("bob", &snap_ok, &wrong_key).is_err());

        // Мусорный/короткий вход.
        assert!(SessionManager::restore("bob", b"not-cbor-at-all", &mk).is_err());
        assert!(SessionManager::restore("bob", &[0u8; 10], &mk).is_err());
    }

    /// Persistence (v6, RT-26.1): смена local_name между snapshot/restore
    /// отклоняется — PQ-ratchet привязан к паре адресов, тихий ребиндинг
    /// сломал бы расшифровку (fail-closed вместо непонятной ошибки позже).
    #[test]
    fn restore_rejects_local_name_mismatch() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        bob.decrypt("alice", &alice.encrypt("bob", b"init").unwrap())
            .unwrap();

        let mk = test_mac_key();
        let snap = bob.snapshot(&mk).unwrap();
        assert!(SessionManager::restore("mallory", &snap, &mk).is_err());
    }

    /// RT-26.1 · P0: crash между decrypt и persistence безопасен от replay.
    /// Инвариант: snapshot, снятый ПОСЛЕ успешного decrypt (persist), делает
    /// повторную доставку того же сообщения rejected (DuplicatedMessage) —
    /// message key не используется второй раз.
    #[test]
    fn crash_between_decrypt_and_persist_is_replay_safe() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();

        let mk = test_mac_key();
        // Сообщение N+1 доставлено и расшифровано; persist снят после.
        let m1 = alice.encrypt("bob", b"secret-N+1").unwrap();
        assert_eq!(bob.decrypt("alice", &m1).unwrap(), b"secret-N+1");
        let snap = bob.snapshot(&mk).unwrap();

        // «Crash» + восстановление из persist-состояния.
        let mut bob2 = SessionManager::restore("bob", &snap, &mk).unwrap();

        // Replay того же ciphertext → обязан быть отклонён (повторное
        // использование message key недопустимо).
        let replay = bob2.decrypt("alice", &m1);
        assert!(
            replay.is_err(),
            "replayed message must be rejected after restore, got {:?}",
            replay.map(|p| String::from_utf8_lossy(&p).to_string())
        );

        // Сессия остаётся рабочей: следующее честное сообщение проходит.
        let m2 = alice.encrypt("bob", b"secret-N+2").unwrap();
        assert_eq!(bob2.decrypt("alice", &m2).unwrap(), b"secret-N+2");
    }
    /// RT-26.13 (O-7): матрица gap-арифметики на чистой функции —
    /// backward-counter, u32-rollover, boundary 99/100, u32::MAX.
    /// Инварианты: (а) нет паник/overflow ни на одной паре;
    /// (б) backward (counter < base) никогда не срабатывает как кап;
    /// (в) гэп ≥ cap детектится на границе ровно.
    #[test]
    fn rt26_13_gap_arithmetic_matrix() {
        // Ровная граница: gap 99 проходит, gap 100 = кап.
        assert!(!gap_exceeds_cap(99, 0));
        assert!(gap_exceeds_cap(100, 0));
        assert!(!gap_exceeds_cap(149, 50));
        assert!(gap_exceeds_cap(150, 50));
        // Backward-counter: relay прислал counter меньше базы (потерянный
        // дубликат старой цепочки) — saturating_sub клампит в 0, кап не
        // срабатывает (решает libsignal: DuplicatedMessage/old counter).
        assert!(!gap_exceeds_cap(99, 100));
        assert!(!gap_exceeds_cap(0, 1));
        // u32-rollover: база у MAX, пришёл counter, обёрнутый в 0 —
        // не паникует и не «капает» (форвард-решение за ratchet).
        assert!(!gap_exceeds_cap(0, u32::MAX));
        assert!(!gap_exceeds_cap(u32::MAX, u32::MAX - 1));
        // Экстремальный форвард-гэп: MAX при базе 0 — кап, без overflow.
        assert!(gap_exceeds_cap(u32::MAX, 0));
    }

    /// RT-26.23 (O-8): replay-матрица — один и тот же ciphertext против
    /// четырёх контекстов состояния: live, после N честных сообщений,
    /// после restore, interleaved с новыми сообщениями. Инвариант: replay
    /// отклонён всюду, сессия не деградирует, новые сообщения проходят.
    #[test]
    fn rt26_23_replay_matrix() {
        let (mut bob, mut alice) = fresh_pair();
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();

        // (1) Replay PreKey-конверта (0x01): one-time prekey уже consumed.
        assert!(
            bob.decrypt("alice", &init_ct).is_err(),
            "prekey envelope replay must fail (one-time prekey consumed)"
        );
        bob.reset_guards();

        // (2) Live: m1 доставлен, replay отклонён, m2 проходит.
        let m1 = alice.encrypt("bob", b"m1").unwrap();
        assert_eq!(bob.decrypt("alice", &m1).unwrap(), b"m1");
        assert!(bob.decrypt("alice", &m1).is_err(), "live replay rejected");
        bob.reset_guards();
        let m2 = alice.encrypt("bob", b"m2").unwrap();
        assert_eq!(bob.decrypt("alice", &m2).unwrap(), b"m2");

        // (3) После restore из persist-состояния: replay m1/m2 отклонён,
        // новое m3 проходит.
        let mk = test_mac_key();
        let snap = bob.snapshot(&mk).unwrap();
        let mut bob2 = SessionManager::restore("bob", &snap, &mk).unwrap();
        assert!(
            bob2.decrypt("alice", &m1).is_err(),
            "m1 replay after restore rejected"
        );
        assert!(
            bob2.decrypt("alice", &m2).is_err(),
            "m2 replay after restore rejected"
        );
        bob2.reset_guards();
        let m3 = alice.encrypt("bob", b"m3").unwrap();
        assert_eq!(bob2.decrypt("alice", &m3).unwrap(), b"m3");

        // (4) Interleaved: m3 → replay m2 → m4: replay не смещает базу
        // (guard_resyncs == 0: resync — только для форвард-гэпа).
        assert!(
            bob2.decrypt("alice", &m2).is_err(),
            "interleaved replay rejected"
        );
        bob2.reset_guards();
        let m4 = alice.encrypt("bob", b"m4").unwrap();
        assert_eq!(bob2.decrypt("alice", &m4).unwrap(), b"m4");
        assert_eq!(
            bob2.guard_resyncs("alice"),
            0,
            "replays must not consume resync (base stays forward)"
        );
    }

    /// RT-26.20 (O-9): hostile-relay state-machine — детерминированный
    /// генератор последовательностей повреждений (drop/dup/reorder/mutate/
    /// replay/truncate/burst) против живой сессии. 5 инвариантов: ни один
    /// plaintext не выдан из повреждённого кадра, сессия не деградирует
    /// (честный кадр после атаки доставляется), base не смещается назад,
    /// guard-resync не съедается атакой, таблица skipped не растёт бесконечно.
    #[test]
    fn hostile_relay_sequence_preserves_session_safety() {
        let (mut bob, mut alice) = fresh_pair();
        let init_ct = alice.encrypt("bob", b"hello").unwrap();
        assert_eq!(bob.decrypt("alice", &init_ct).unwrap(), b"hello");
        bob.reset_guards();

        // Детерминированный LCG — без rand-зависимости в тесте.
        let mut seed: u64 = 0x4D494E;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        // 40 раундов: атака над честным кадром + честный кадр.
        // MIN-28 (RT-26.20): libsignal-сериализация не канонична (protobuf):
        // часть байт-мутаций семантически нейтральна и даёт тот же plaintext.
        // Инвариант: мутация никогда не даёт ДРУГОЙ plaintext и никогда не
        // смещает базу счётчика; на wire MIN это дополнительно закрыто
        // внешним AEAD + commitment (конверт отбракует такие байты до
        // libsignal). Если мутация «прошла» — раунд считается доставленным.
        for round in 0..40u32 {
            let msg = format!("r{}", round);
            let expected = msg.clone().into_bytes();
            let mut delivered = false;

            // Мутация случайного байта.
            let mut evil = alice.encrypt("bob", msg.as_bytes()).unwrap();
            let pos = (rng() as usize) % evil.len();
            evil[pos] ^= 0x5A;
            match bob.decrypt("alice", &evil) {
                Ok(pt) => {
                    assert_eq!(
                        pt, expected,
                        "mutated frame must never yield DIFFERENT plaintext"
                    );
                    delivered = true;
                }
                Err(_) => {}
            }

            // Truncation до случайной длины — всегда отказ.
            let honest_ct = if delivered {
                alice.encrypt("bob", &expected).unwrap()
            } else {
                let ct = alice.encrypt("bob", msg.as_bytes()).unwrap();
                let cut = 1 + (rng() as usize) % ct.len().saturating_sub(1);
                assert!(
                    bob.decrypt("alice", &ct[..cut]).is_err(),
                    "truncated frame must be rejected"
                );
                ct
            };

            // Честный кадр доставляется; повтор — нет.
            assert_eq!(
                bob.decrypt("alice", &honest_ct).unwrap(),
                msg.as_bytes(),
                "honest frame after attacks must deliver"
            );
            assert!(
                bob.decrypt("alice", &honest_ct).is_err(),
                "no double-delivery of the same frame"
            );

            // Инвариант раунда: атаки НЕ смещают базу счётчика
            // (resync — только для честного форвард-гэпа).
            assert_eq!(
                bob.guard_resyncs("alice"),
                0,
                "hostile mutations must never resync the counter base"
            );
            bob.reset_guards();
        }
    }

    /// RT-26.2 (O-9): rollback валидного бэкапа после revoke. Snapshot
    /// легитимного устройства (MAC корректен) с отпечатком отозванного
    /// identity должен быть отклонён restore_checked, но обычный restore
    /// и restore_checked без revoke-листа работают как раньше.
    #[test]
    fn stale_backup_after_revoke_is_rejected() {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        bob.decrypt("alice", &alice.encrypt("bob", b"init").unwrap())
            .unwrap();

        let mk = test_mac_key();
        let snap = bob.snapshot(&mk).unwrap();
        let fp = identity_fingerprint(&bob.identity_key_public());

        // Без revoke-листа restore_checked эквивалентен restore.
        assert!(SessionManager::restore_checked("bob", &snap, &mk, &[]).is_ok());

        // Отзыв: реставрация бэкапа отозванного identity → отказ (даже при
        // валидном MAC: rollback-реставрация отозванного ключа закрыта).
        assert!(matches!(
            SessionManager::restore_checked("bob", &snap, &mk, &[fp]),
            Err(crate::SessionError::RevokedIdentity)
        ));

        // Другой fingerprint в списке — не блокирует.
        assert!(SessionManager::restore_checked("bob", &snap, &mk, &[[9u8; 16]]).is_ok());

        // Отпечаток внутри MACed-блоба: тампер fp → MAC-отказ (fail-closed).
        let mut tampered = snap.clone();
        let fp_pos = tampered.len() - 32 - 1; // последний байт CBOR-тела
        tampered[fp_pos] ^= 0x01;
        assert!(SessionManager::restore_checked("bob", &tampered, &mk, &[]).is_err());
    }

    /// RT-26.10: cross-direction state confusion — чужое направление не
    /// двигает состояние. Ciphertext alice→bob, поданный alice как входящий
    /// от bob (и наоборот), отклоняется без сдвига ratchet/guard.
    #[test]
    fn cross_direction_replay_never_advances_peer_state() {
        let (mut bob, mut alice) = fresh_pair();
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice.init_session("bob", &bundle).unwrap();
        let init_ct = alice.encrypt("bob", b"init").unwrap();
        bob.decrypt("alice", &init_ct).unwrap();

        // Честный трафик a→b: m1 доставлен bob.
        let m1 = alice.encrypt("bob", b"m1").unwrap();
        assert_eq!(bob.decrypt("alice", &m1).unwrap(), b"m1");

        // Cross-direction: m1 (a→b) предъявлен alice как сообщение от bob.
        assert!(
            alice.decrypt("bob", &m1).is_err(),
            "a→b ciphertext must not decrypt in alice's b→a direction"
        );
        alice.reset_guards();

        // State alice не сдвинулся: честное b→a сообщение проходит.
        let ack = bob.encrypt("alice", b"ack").unwrap();
        assert_eq!(alice.decrypt("bob", &ack).unwrap(), b"ack");

        // И симметрично: ack (b→a) предъявлен bob как a→b.
        assert!(
            bob.decrypt("alice", &ack).is_err(),
            "b→a ciphertext must not decrypt in bob's a→b direction"
        );
        bob.reset_guards();
        let m2 = alice.encrypt("bob", b"m2").unwrap();
        assert_eq!(bob.decrypt("alice", &m2).unwrap(), b"m2");
    }

    /// RT-26.9 / MIN-26: ротация Contact Key (epoch 1 → 2) закрывает прежний
    /// адрес: старая сессия не остаётся живой, rollback эпохи и подмена адреса
    /// при той же эпохе отвергаются, состояние эпох переживает restore.
    #[test]
    fn revoked_contact_key_cannot_keep_old_session_alive() {
        use min_identity::{mailbox_id, EPOCH_INITIAL};

        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();

        // Identity пира (bob): libsignal serialize() = 0x05 || 32 байта.
        let bob_pub = bob.identity_key_public();
        let pk: [u8; 32] = bob_pub[1..33].try_into().unwrap();
        let id_hex = hex::encode(pk);
        let addr1 = hex::encode(mailbox_id(&pk, EPOCH_INITIAL));
        let addr2 = hex::encode(mailbox_id(&pk, EPOCH_INITIAL + 1));
        let addr_bogus = hex::encode([0xAB; 16]);

        // (1) Первая привязка: адрес эпохи 1, сессия работает.
        let bundle1 = bob.generate_prekey_bundle().unwrap();
        let rotated = alice
            .init_session_with_contact_key(&id_hex, &addr1, EPOCH_INITIAL, &bundle1)
            .unwrap();
        assert!(!rotated, "first bind is not a rotation");
        let ct1 = alice.encrypt(&addr1, b"epoch-1").unwrap();
        assert_eq!(bob.decrypt("alice", &ct1).unwrap(), b"epoch-1");

        // (2) Ротация: тот же identity, новая эпоха — новый адрес.
        let bundle2 = bob.generate_prekey_bundle().unwrap();
        let rotated = alice
            .init_session_with_contact_key(&id_hex, &addr2, EPOCH_INITIAL + 1, &bundle2)
            .unwrap();
        assert!(rotated, "epoch growth must be reported as rotation");
        assert!(
            alice.is_stale_address(&addr1),
            "previous address must be closed"
        );

        // (3) Старый адрес — мёртвый маршрут (guard до криптографии).
        assert!(matches!(
            alice.encrypt(&addr1, b"to-stale"),
            Err(SessionError::EpochRotated)
        ));
        assert!(matches!(
            alice.decrypt(&addr1, &ct1),
            Err(SessionError::EpochRotated)
        ));

        // (4) Rollback Contact Key (эпоха 1 снова) отвергается.
        assert!(matches!(
            alice.init_session_with_contact_key(&id_hex, &addr1, EPOCH_INITIAL, &bundle1),
            Err(SessionError::EpochRotated)
        ));
        // (5) Та же эпоха, но чужой адрес — расхождение с PROTOCOL §5.
        assert!(matches!(
            alice.init_session_with_contact_key(&id_hex, &addr_bogus, EPOCH_INITIAL + 1, &bundle2),
            Err(SessionError::EpochRotated)
        ));
        // (6) epoch 0 не существует (fail-closed).
        assert!(matches!(
            alice.init_session_with_contact_key(&id_hex, &addr_bogus, 0, &bundle2),
            Err(SessionError::EpochRotated)
        ));

        // (7) Новая эпоха полностью работоспособна.
        let ct2 = alice.encrypt(&addr2, b"epoch-2").unwrap();
        assert_eq!(bob.decrypt("alice", &ct2).unwrap(), b"epoch-2");

        // (8) Restore: состояние эпох внутри MACed-блоба, откат бэкапа не
        //     оживляет ротированный адрес.
        let mk = test_mac_key();
        let snap = alice.snapshot(&mk).unwrap();
        let mut alice2 = SessionManager::restore("alice", &snap, &mk).unwrap();
        assert!(
            alice2.is_stale_address(&addr1),
            "stale state must survive restore"
        );
        assert!(matches!(
            alice2.encrypt(&addr1, b"after-restore"),
            Err(SessionError::EpochRotated)
        ));
        let ct3 = alice2.encrypt(&addr2, b"epoch-2b").unwrap();
        assert_eq!(bob.decrypt("alice", &ct3).unwrap(), b"epoch-2b");
    }

    // ---- MIN-RED-022: первое сообщение от незнакомца --------------------
    //
    // ВАЖНО: адрес в libsignal ЛОКАЛЬНЫЙ. «Имя пира» на стороне получателя
    // и «имя получателя» на стороне отправителя — РАЗНЫЕ строки, и совпадать
    // они не обязаны (у отправителя это hex identity ПОЛУЧАТЕЛЯ из его
    // Contact Key, у получателя — hex identity ОТПРАВИТЕЛЯ, извлечённый из
    // самого PreKey-сообщения). Криптографию связывает не имя, а
    // выведенный при handshake общий секрет.

    /// Возвращает (bob, alice, bob_id). У bob НЕТ ни одной сессии; alice
    /// знает только Contact Key bob'а и пишет ему первой.
    fn stranger_scenario() -> (SessionManager, SessionManager, String) {
        let mut bob = SessionManager::new("bob").unwrap();
        let mut alice = SessionManager::new("alice").unwrap();
        let bob_id = hex::encode(&bob.identity_key_public()[1..]);
        let bundle = bob.generate_prekey_bundle().unwrap();
        alice
            .init_session_from_invite(&bob_id, &bob_id, 1, &bundle)
            .unwrap();
        (bob, alice, bob_id)
    }

    /// Базовый сценарий: незнакомец присылает первое сообщение, получатель
    /// принимает его, видит отправителя и может продолжить переписку.
    ///
    /// ЗАМЕЧАНИЕ О ПРОТОКОЛЕ (проверено тестом, а не предположено):
    /// инициатор шлёт PreKey-сообщения, ПОКА не получит ответ от второй
    /// стороны. Это штатное поведение libsignal: у отправителя нет
    /// подтверждения, что сессия, поэтому он пересылает prekey-сообщение
    /// (это же даёт устойчивость к потере сообщения). Первым whisper может
    /// стать только ответ ПОЛУЧАТЕЛЯ. Это не баг и не регрессия.
    #[test]
    fn stranger_first_message_establishes_session() {
        let (mut bob, mut alice, bob_id) = stranger_scenario();
        let first = alice.encrypt(&bob_id, b"hello from stranger").unwrap();
        assert_eq!(
            msg_type_of(&first),
            "prekey",
            "first contact must be PreKey"
        );

        let contact = bob.accept_from_stranger(&first).unwrap();
        assert_eq!(contact.plaintext, b"hello from stranger");
        assert_eq!(contact.peer_identity.len(), 32);
        assert_eq!(
            contact.peer_name,
            hex::encode(&alice.identity_key_public()[1..]),
            "receiver must name the peer by hex of the SENDER identity"
        );

        // Ответ получателя — уже обычный whisper: сессия установлена.
        let reply = bob.encrypt(&contact.peer_name, b"hi, accepted").unwrap();
        assert_eq!(msg_type_of(&reply), "whisper");
        assert_eq!(alice.decrypt(&bob_id, &reply).unwrap(), b"hi, accepted");

        // И только после получения ответа инициатор переходит на whisper.
        let next = alice.encrypt(&bob_id, b"reply to stranger").unwrap();
        assert_eq!(msg_type_of(&next), "whisper");
        assert_eq!(
            bob.decrypt(&contact.peer_name, &next).unwrap(),
            b"reply to stranger"
        );
    }

    /// Replay первого сообщения недопустим: тот же конверт второй раз
    /// расшифрован быть не может (libsignal отвергнет повторный PreKey).
    #[test]
    fn stranger_first_message_replay_is_rejected() {
        let (mut bob, mut alice, bob_id) = stranger_scenario();
        let first = alice.encrypt(&bob_id, b"once").unwrap();
        bob.accept_from_stranger(&first).unwrap();
        assert!(
            bob.accept_from_stranger(&first).is_err(),
            "replayed first contact must not be accepted twice"
        );
    }

    /// Подмена первого сообщения ломает расшифровку (AEAD / подпись identity).
    #[test]
    fn stranger_first_message_tamper_is_rejected() {
        let (mut bob, mut alice, bob_id) = stranger_scenario();
        let first = alice.encrypt(&bob_id, b"orig").unwrap();
        let mut bad = first.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(
            bob.accept_from_stranger(&bad).is_err(),
            "tampered first contact must be rejected"
        );
    }

    /// Настоящий whisper (0x02) методом «первого сообщения» принять нельзя:
    /// без PreKey-конверта инициатор неизвестен.
    #[test]
    fn stranger_accept_requires_prekey_message() {
        let (mut bob, mut alice, bob_id) = stranger_scenario();
        let first = alice.encrypt(&bob_id, b"first").unwrap();
        let contact = bob.accept_from_stranger(&first).unwrap();

        // Настоящий whisper: получатель отвечает, инициатор читает.
        let reply = bob.encrypt(&contact.peer_name, b"answer").unwrap();
        assert_eq!(msg_type_of(&reply), "whisper");
        alice.decrypt(&bob_id, &reply).unwrap();

        // Ни получатель (уже знающий отправителя), ни посторонний не могут
        // принять whisper методом «первого сообщения».
        assert!(bob.accept_from_stranger(&reply).is_err());
        let mut carol = SessionManager::new("carol").unwrap();
        assert!(carol.accept_from_stranger(&reply).is_err());
    }

    /// Пустой и короткий вход не должны паниковать.
    #[test]
    fn stranger_accept_rejects_malformed_input() {
        let mut bob = SessionManager::new("bob").unwrap();
        assert!(bob.accept_from_stranger(&[]).is_err(), "empty input");
        assert!(bob.accept_from_stranger(&[0x01]).is_err(), "type byte only");
        assert!(
            bob.accept_from_stranger(&[0xff, 0x00, 0x01]).is_err(),
            "unknown type byte"
        );
    }

    /// Принятие незнакомца НЕ должно ломать уже установленные сессии
    /// (защита от DoS через перезапись session record).
    #[test]
    fn stranger_accept_does_not_disturb_known_sessions() {
        let (mut bob, mut alice) = handshaken_pair();
        let before = bob
            .decrypt("alice", &alice.encrypt("bob", b"1").unwrap())
            .unwrap();

        // Приходит «незнакомец» dave: у него есть Contact Key ИМЕННО bob'а.
        let bob_id = hex::encode(&bob.identity_key_public()[1..]);
        let bob_bundle = bob.generate_prekey_bundle().unwrap();
        let mut dave = SessionManager::new("dave").unwrap();
        dave.init_session_from_invite(&bob_id, &bob_id, 1, &bob_bundle)
            .unwrap();
        let stranger_msg = dave.encrypt(&bob_id, b"hello from dave").unwrap();
        let contact = bob.accept_from_stranger(&stranger_msg).unwrap();
        assert_eq!(contact.plaintext, b"hello from dave");

        // Переписка с Алисой жива и продолжает работать.
        let after = bob
            .decrypt("alice", &alice.encrypt("bob", b"2").unwrap())
            .unwrap();
        assert_eq!(after, b"2");
        assert_eq!(before, b"1");
    }
}
