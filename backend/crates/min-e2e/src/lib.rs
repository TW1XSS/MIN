//! MIN E2E — сквозной зашифрованный поток: Алиса → relay → Боб (ТЗ §44, этап 9).
//!
//! Проверяет главный слоган MIN: «сервер — глухой почтальон».
//! Relay видит только opaque ciphertext (hex), ни одного байта plaintext.

use min_crypto::{decrypt, encrypt, generate_keypair, PublicKey, SecretKey, PRIMITIVE_AAD};
use rand_core::RngCore;

/// Один контакт в памяти (мини-модель клиента, без persistence).
pub struct Peer {
    pub display_name: String,
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Peer {
    pub fn new(name: String) -> Self {
        let (sk, pk) = generate_keypair().expect("X25519 keypair generation failed");
        Self {
            display_name: name,
            secret: sk,
            public: pk,
        }
    }

    /// Общий ключ с собеседником (это делает каждый клиент локально).
    pub fn shared_with(&self, peer: &Peer) -> min_crypto::SharedSecret {
        min_crypto::derive_shared_secret(&self.secret, &peer.public)
            .expect("DH shared secret failed")
    }
}

/// Зашифрованное сообщение, готовое к отправке через relay.
pub struct CipherMessage {
    /// Куда доставить (mailbox id получателя).
    pub to: String,
    /// opaque ciphertext в hex — единственное, что видит relay.
    pub envelope_hex: String,
}

/// Шифрует сообщение и кладёт в очередь адресата на relay.
pub fn send(
    store: &mut min_relay::store::Store,
    from: &Peer,
    to_id: &str,
    to: &Peer,
    text: &str,
) -> CipherMessage {
    let shared = from.shared_with(to);
    // AUDIT FIX-1: домен примитивного слоя вместо пустого AAD.
    let sealed = encrypt(&shared, text.as_bytes(), PRIMITIVE_AAD).expect("encrypt failed");
    let envelope_hex = hex::encode(&sealed);

    let item = min_relay::store::QueueItem {
        item_id: format!("msg-{}", rand_id()),
        envelope_hex: envelope_hex.clone(),
        arrived_at: now_sec(),
        expires_at: now_sec() + 14 * 24 * 3600,
        item_type: min_relay::store::ItemType::Message,
        acked: false,
    };
    store.enqueue(to_id, item).expect("enqueue failed");

    CipherMessage {
        to: to_id.to_string(),
        envelope_hex,
    }
}

/// Забирает сообщения из очереди адресата и расшифровывает каждое.
pub fn receive(
    store: &min_relay::store::Store,
    me_id: &str,
    me: &Peer,
    from: &Peer,
    count: usize,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mb = match store.get(me_id) {
        Some(mb) => mb,
        None => return out,
    };
    let shared = me.shared_with(from);
    for item in mb.queue.iter().filter(|q| !q.acked).take(count) {
        let sealed = hex::decode(&item.envelope_hex).expect("hex decode failed");
        // AUDIT FIX-1: домен примитивного слоя вместо пустого AAD.
        let plain = decrypt(&shared, &sealed, PRIMITIVE_AAD).expect("decrypt failed");
        out.push(String::from_utf8(plain).expect("plaintext must be utf-8"));
    }
    out
}

/// Ack — сообщение подтверждено, relay может забыть его.
pub fn ack(store: &mut min_relay::store::Store, me_id: &str) -> usize {
    let item_ids: Vec<String> = match store.get(me_id) {
        Some(mb) => mb
            .queue
            .iter()
            .filter(|q| !q.acked)
            .map(|q| q.item_id.clone())
            .collect(),
        None => return 0,
    };

    let mut n = 0;
    for id in item_ids {
        if store.ack(me_id, &id) {
            n += 1;
        }
    }
    n
}

fn rand_id() -> u64 {
    let mut buf = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

fn now_sec() -> u64 {
    // mock-часы для тестов (детерминизм).
    1_700_000_000u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_store() -> (min_relay::store::Store, &'static str, &'static str) {
        let mut store = min_relay::store::Store::new();
        store.register("alice-mbx".into()).expect("register alice");
        store.register("bob-mbx".into()).expect("register bob");
        (store, "alice-mbx", "bob-mbx")
    }

    /// Главный сценарий: Алиса шифрует → relay хранит hex → Боб расшифровывает.
    #[test]
    fn alice_to_bob_via_relay_roundtrip() {
        let (mut store, alice_id, bob_id) = registered_store();
        let alice = Peer::new("Alice".into());
        let bob = Peer::new("Bob".into());

        let m1 = send(&mut store, &alice, bob_id, &bob, "Hello Bob!");
        let m2 = send(&mut store, &alice, bob_id, &bob, "Trust the min!");
        assert_eq!(m1.to, bob_id);
        assert_eq!(m2.to, bob_id);

        // Боб получает и расшифровывает оба сообщения по порядку.
        let received = receive(&store, bob_id, &bob, &alice, 10);
        assert_eq!(
            received,
            vec!["Hello Bob!".to_string(), "Trust the min!".to_string()]
        );

        // Симметрия: Боб тоже может отправить, Алиса прочитает.
        send(&mut store, &bob, alice_id, &alice, "Hi Alice!");
        let back = receive(&store, alice_id, &alice, &bob, 10);
        assert_eq!(back, vec!["Hi Alice!".to_string()]);
    }

    /// Relay-изоляция (ТЗ §12.2): в store нет ни одного байта plaintext.
    #[test]
    fn relay_never_sees_plaintext() {
        let (mut store, _alice_id, bob_id) = registered_store();
        let alice = Peer::new("Alice".into());
        let bob = Peer::new("Bob".into());

        let secrets = ["Hello Bob!", "the quick brown fox", "secret-123"];
        for s in secrets {
            send(&mut store, &alice, bob_id, &bob, s);
        }

        let dumped = format!("{store:?}");
        for s in secrets {
            assert!(
                !dumped.contains(s),
                "plaintext {s:?} leaked into relay store"
            );
        }

        // Всё, что лежит в очереди — валидный hex (opaque ciphertext).
        let mb = store.get(bob_id).unwrap();
        assert_eq!(mb.queue.len(), secrets.len());
        for item in &mb.queue {
            let raw = hex::decode(&item.envelope_hex).expect("envelope must be hex");
            // nonce(24) + tag(16) — минимум даже для пустого сообщения.
            assert!(raw.len() > 24 + 16, "envelope too short to be sealed");
        }
    }

    /// Mallory с подменёнными ключами не может расшифровать чужой трафик.
    #[test]
    fn interlopers_cannot_decrypt() {
        let (mut store, _alice_id, bob_id) = registered_store();
        let alice = Peer::new("Alice".into());
        let bob = Peer::new("Bob".into());
        let mallory = Peer::new("Mallory".into());

        let sealed_hex = send(&mut store, &alice, bob_id, &bob, "private").envelope_hex;
        let sealed = hex::decode(&sealed_hex).unwrap();

        // Mallory делает DH со СВОИМ секретом против публичного ключа Алисы —
        // HKDF даёт другой ключ, AEAD-тег не сходится.
        let mallory_shared =
            min_crypto::derive_shared_secret(&mallory.secret, &alice.public).unwrap();
        assert!(matches!(
            min_crypto::decrypt(&mallory_shared, &sealed, PRIMITIVE_AAD),
            Err(min_crypto::CryptoError::DecryptionFailed)
        ));

        // И даже её «правильный» общий ключ с Бобом не подходит.
        let mallory_bob = min_crypto::derive_shared_secret(&mallory.secret, &bob.public).unwrap();
        assert!(matches!(
            min_crypto::decrypt(&mallory_bob, &sealed, PRIMITIVE_AAD),
            Err(min_crypto::CryptoError::DecryptionFailed)
        ));
    }

    /// AUDIT FIX-1 (красная команда): контекстная подмена AAD.
    /// Шифротекст примитивного слоя НЕ расшифровывается с пустым AAD
    /// (и наоборот) — контекст использования привязан к AEAD-тегу.
    #[test]
    fn aad_context_substitution_rejected() {
        let alice = Peer::new("A".into());
        let bob = Peer::new("B".into());
        let shared = alice.shared_with(&bob);
        let sealed = min_crypto::encrypt(&shared, b"context test", PRIMITIVE_AAD).unwrap();

        // Расшифровка с пустым AAD (другой контекст) → отказ.
        assert!(matches!(
            min_crypto::decrypt(&shared, &sealed, b""),
            Err(min_crypto::CryptoError::DecryptionFailed)
        ));
        // С чужим доменом → отказ.
        assert!(matches!(
            min_crypto::decrypt(&shared, &sealed, b"min-recovery/v1"),
            Err(min_crypto::CryptoError::DecryptionFailed)
        ));
        // С правильным доменом → расшифровка.
        assert_eq!(
            min_crypto::decrypt(&shared, &sealed, PRIMITIVE_AAD).unwrap(),
            b"context test"
        );
    }

    /// Ack: подтверждённые сообщения выходят из выдачи receive().
    #[test]
    fn ack_removes_from_pending() {
        let (mut store, alice_id, bob_id) = registered_store();
        let alice = Peer::new("Alice".into());
        let bob = Peer::new("Bob".into());

        send(&mut store, &alice, bob_id, &bob, "one");
        send(&mut store, &alice, bob_id, &bob, "two");
        assert_eq!(receive(&store, bob_id, &bob, &alice, 10).len(), 2);

        let acked = ack(&mut store, bob_id);
        assert_eq!(acked, 2);
        assert!(receive(&store, bob_id, &bob, &alice, 10).is_empty());

        // Ack несуществующего mailbox безопасен.
        assert_eq!(ack(&mut store, alice_id), 0);
    }
}
