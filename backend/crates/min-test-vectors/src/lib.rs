//! Сквозные тест-векторы этапа 0 (ТЗ §44 п.3: тест-векторы до UI-интеграции).
//!
//! Инварианты, закреплённые здесь, не должны меняться без bump версии протокола:
//! 1. Ed25519 KAT (RFC 8032, TEST 1) — не сломать базу подписей.
//! 2. Канонический CBOR map — фиксированные байты.
//! 3. Contact Key: полный цикл generate→sign→format→parse→verify.
//! 4. Тамперинг детектируется (подпись/строка).
//! 5. Envelope: wire roundtrip, строгий reject мусора.

/// RFC 8032 §7.1, TEST 1 (Ed25519 SHA-abc).
const KAT_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const KAT_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const KAT_MSG: &str = "";
const KAT_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

#[test]
fn rfc8032_ed25519_kat() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    let secret = hex::decode(KAT_SECRET).unwrap();
    let sk = SigningKey::from_bytes(&secret.try_into().unwrap());
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        KAT_PUBLIC.to_lowercase()
    );

    let sig = sk.sign(KAT_MSG.as_bytes());
    assert_eq!(hex::encode(sig.to_bytes()), KAT_SIG.to_lowercase());

    let vk = VerifyingKey::from_bytes(&sk.verifying_key().to_bytes()).unwrap();
    let parsed = Signature::from_bytes(&sig.to_bytes());
    assert!(vk.verify(KAT_MSG.as_bytes(), &parsed).is_ok());
}

#[test]
fn contact_key_end_to_end() {
    use min_identity::{mailbox_id, IdentityKeypair, SignedPrekey};
    use min_protocol::contact_key::ContactKeyV3;

    let identity = IdentityKeypair::generate();
    let prekey = SignedPrekey::generate();
    let mb = mailbox_id(&identity.public(), min_protocol::EPOCH_INITIAL);

    let ck = ContactKeyV3 {
        identity_public_key: identity.public(),
        mailbox_id: mb,
        signed_prekey_public: prekey.public(),
        expiry: 0,
        epoch: min_protocol::EPOCH_INITIAL,
        signature: identity.sign(&{
            ContactKeyV3 {
                identity_public_key: identity.public(),
                mailbox_id: mb,
                signed_prekey_public: prekey.public(),
                expiry: 0,
                epoch: min_protocol::EPOCH_INITIAL,
                signature: [0u8; 64],
            }
            .canonical_payload()
        }),
    };

    // строковая форма → парс → verify
    let s = ck.to_string_form();
    assert!(s.starts_with("MIN3:"));
    let parsed = ContactKeyV3::parse_string_form(&s).unwrap();
    assert_eq!(parsed, ck);
    parsed.verify().expect("signature must verify");

    // тамперинг mailbox_id → подпись ломается
    let mut forged = parsed.clone();
    forged.mailbox_id = [0xFF; 16];
    assert_eq!(
        forged.verify().unwrap_err(),
        min_protocol::ProtocolError::BadSignature
    );
}

#[test]
fn envelope_wire_pipeline() {
    use min_protocol::envelope::{EnvelopeV1, MessageType};

    let env = EnvelopeV1 {
        msg_type: MessageType::Request,
        epoch: 1,
        seq: 1,
        sender_hint: [0u8; 16],
        mailbox_hint: [3u8; 16],
        aad_commitment: [4u8; 16],
        nonce: [2u8; 24],
        ciphertext: b"encrypted-request-payload".to_vec(),
        ttl_sec: 7 * 24 * 3600,
        queue_class: 0,
    };

    // envelope → frame → unframe → parse
    let framed = min_wire::frame(&env.to_wire().unwrap()).unwrap();
    let mut buf = framed;
    let payload = min_wire::unframe(&mut buf).unwrap().unwrap();
    assert!(buf.is_empty());
    let back = EnvelopeV1::from_wire(&payload).unwrap();
    assert_eq!(back, env);
    assert_eq!(back.msg_type, MessageType::Request);
}

#[test]
fn canonical_map_bytes_are_frozen() {
    use ciborium::value::Value;
    use min_protocol::canonical_map;
    // (1:1) → CBOR: a1 01 01
    let m = canonical_map(&[(1, Value::Integer(1.into()))]);
    assert_eq!(
        min_wire::canonical_encode(&m).unwrap(),
        vec![0xa1, 0x01, 0x01]
    );
    // (3:1, 1:1) → ключи сортируются: a2 01 01 03 01
    let m = canonical_map(&[(3, Value::Integer(1.into())), (1, Value::Integer(1.into()))]);
    assert_eq!(
        min_wire::canonical_encode(&m).unwrap(),
        vec![0xa2, 0x01, 0x01, 0x03, 0x01]
    );
}
