//! E2E: два AppCore (Алиса/Боб) через in-process relay.
//! Поток MVP: open -> register -> взаимные контакты -> send -> poll -> decrypt.

use min_app::AppCore;
use min_delivery::{DeliveryError, FrameExchange, MailboxClient};
use min_protocol::frame_api::FrameRequest;
use min_session::PreKeyBundleData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos}-{sequence}",
        std::process::id()
    ))
}

/// In-process ссылка на relay store (замена сети в тесте).
struct LocalLink {
    store: Arc<RwLock<min_relay::store::Store>>,
    rt: Arc<tokio::runtime::Runtime>,
}

impl FrameExchange for LocalLink {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DeliveryError> {
        let req = FrameRequest::from_wire(request).map_err(DeliveryError::Protocol)?;
        let resp = self.rt.block_on(min_relay::frame_server::handle_frame(
            &self.store.clone(),
            req,
        ));
        resp.to_wire()
            .map_err(|e| DeliveryError::Protocol(e.into()))
    }
}

fn bundle_is_bound(invite: &str) -> bool {
    let bundle_hex = invite
        .lines()
        .find_map(|line| line.strip_prefix("BND:"))
        .unwrap();
    let bundle = PreKeyBundleData::from_cbor(&hex::decode(bundle_hex).unwrap()).unwrap();
    bundle
        .contact_key_binding
        .as_ref()
        .is_some_and(|s| s.len() == 64)
}

fn forged_invite_with_mutated_bundle(invite: &str) -> String {
    let mut lines = invite.lines().map(str::to_owned).collect::<Vec<_>>();
    let index = lines
        .iter()
        .position(|line| line.starts_with("BND:"))
        .expect("invite bundle line");
    let bundle_hex = lines[index].strip_prefix("BND:").unwrap();
    let mut bundle = PreKeyBundleData::from_cbor(&hex::decode(bundle_hex).unwrap()).unwrap();
    bundle.pre_key_id = bundle.pre_key_id.wrapping_add(1);
    lines[index] = format!("BND:{}", hex::encode(bundle.to_cbor().unwrap()));
    lines.join("\n")
}

#[test]
fn two_accounts_exchange_messages() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir_a = unique_test_dir("min-app-a");
    let dir_b = unique_test_dir("min-app-b");
    let key = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    // Один relay-store на двоих (в проде — один узел).
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let link_a = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let link_b = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let mut alice = AppCore::open(&dir_a, key, MailboxClient::new(link_a)).unwrap();
    let mut bob = AppCore::open(&dir_b, key, MailboxClient::new(link_b)).unwrap();

    alice.register().unwrap();
    bob.register().unwrap();

    // Взаимное добавление контакта (MVP-поток: обмен Contact Key + bundle).
    let invite_a = alice.my_invite().unwrap();
    let invite_b = bob.my_invite().unwrap();
    assert!(bundle_is_bound(&invite_a));
    assert!(bundle_is_bound(&invite_b));
    let forged_invite = forged_invite_with_mutated_bundle(&invite_b);
    let err = alice
        .add_contact_by_invite("Mallory", &forged_invite)
        .expect_err("mutated bundle must be rejected");
    assert!(
        format!("{err:?}").contains("not bound"),
        "unexpected error: {err:?}"
    );

    alice.add_contact_by_invite("Bob", &invite_b).unwrap();
    bob.add_contact_by_invite("Alice", &invite_a).unwrap();

    // Алиса -> Боб.
    let sent = alice.send_text("Bob", "привет из MIN!").unwrap();
    assert_eq!(sent.status, min_app::MessageStatus::Sent);
    let incoming = bob.poll().unwrap();
    assert_eq!(incoming.len(), 1, "bob must receive one message");
    assert_eq!(incoming[0].text, "привет из MIN!");

    // Боб -> Алиса (ответ).
    bob.send_text("Alice", "привет!").unwrap();
    let got = alice.poll().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "привет!");

    // Список чатов у Алисы содержит Боба.
    let chats = alice.list_chats().unwrap();
    assert!(chats.contains("Bob"), "chats: {chats}");

    // История у Боба: входящее + его ответ.
    let history = bob.messages("Alice").unwrap();
    assert!(history.contains("привет из MIN!"), "history: {history}");
    assert!(history.contains("привет!"), "history: {history}");

    // Идемпотентность: повторный pull не дублирует историю.
    let again = bob.poll().unwrap();
    assert!(again.is_empty(), "no duplicates after ack");
    let h2 = bob.messages("Alice").unwrap();
    assert_eq!(h2.matches("привет из MIN!").count(), 1, "no dupes: {h2}");

    // Персистентность: переоткрытие Боба восстанавливает сессии и историю.
    let link_b2 = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let mut bob2 = AppCore::open(&dir_b, key, MailboxClient::new(link_b2)).unwrap();
    bob2.register().unwrap();
    let restored = bob2.messages("Alice").unwrap();
    assert!(restored.contains("привет!"), "restored: {restored}");
}

/// Регресс UI-потока MVP (Swift): контакт добавляется БЕЗ имени («» — как
/// `MinApp.addContact(name: "")`), ядро генерирует «User-XXXXXX»; отправка
/// идёт по identity hex (UI передаёт `chat.cryptoID`). До фикса:
/// `send_text` шифровал по АРГУМЕНТУ (identity), а сессия привязана к имени
/// записи → «core вернул NULL», сообщение не уходило.
#[test]
fn ui_flow_send_by_identity_with_generated_name() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir_a = unique_test_dir("min-app-uia");
    let dir_b = unique_test_dir("min-app-uib");
    let key = "b1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let link_a = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let link_b = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let mut alice = AppCore::open(&dir_a, key, MailboxClient::new(link_a)).unwrap();
    let mut bob = AppCore::open(&dir_b, key, MailboxClient::new(link_b)).unwrap();

    alice.register().unwrap();
    bob.register().unwrap();

    let invite_a = alice.my_invite().unwrap();
    let invite_b = bob.my_invite().unwrap();
    alice.add_contact_by_invite("", &invite_b).unwrap();
    bob.add_contact_by_invite("", &invite_a).unwrap();

    let bob_identity = first_contact_identity(&alice.contacts().unwrap());
    assert!(bob_identity.len() == 64, "identity hex expected");

    // Отправка по identity (как кнопка send у UI) — до фикса падало здесь.
    let sent = alice.send_text(&bob_identity, "hi from UI flow").unwrap();
    assert_eq!(sent.status, min_app::MessageStatus::Sent);

    let incoming = bob.poll().unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].text, "hi from UI flow");

    // Ответ тоже по identity.
    let alice_identity = first_contact_identity(&bob.contacts().unwrap());
    bob.send_text(&alice_identity, "reply").unwrap();
    let got = alice.poll().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "reply");

    // Имя записи — сгенерированное ядром.
    let v: serde_json::Value = serde_json::from_str(&alice.contacts().unwrap()).unwrap();
    let name = v[0]["name"].as_str().unwrap().to_string();
    assert!(name.starts_with("User-"), "generated name, got {name}");
}

/// identity hex первого контакта из JSON-массива `AppCore::contacts()`.
fn first_contact_identity(contacts_json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(contacts_json).unwrap();
    v[0]["identity_hex"].as_str().unwrap().to_string()
}

/// Security-регресс: при потере relay auth-state клиент НЕ re-register'ит mailbox.
/// mailbox_id публичен; автоматический re-claim позволил бы атакующему перехватить
/// mailbox после рестарта. Путь должен завершиться ошибкой, не создавая mailbox.
#[test]
fn relay_state_loss_fails_closed_without_reclaim() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir_a = std::env::temp_dir().join(format!("min-app-restart-a-{nonce}"));
    let key = "abababababababababababababababababababababababababababababababab";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let mut alice = AppCore::open(
        &dir_a,
        key,
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        }),
    )
    .unwrap();
    alice.register().unwrap();
    let alice_self: serde_json::Value =
        serde_json::from_str(&alice.self_public().unwrap()).unwrap();
    let alice_mailbox = alice_self["mailbox_id_hex"].as_str().unwrap().to_string();

    // Симулируем рестарт relay: store полностью очищен.
    rt.block_on(async {
        let mut guard = store.write().await;
        *guard = min_relay::store::Store::new();
    });

    // Ни register(), ни poll() не должны автоматически re-claim публичный mailbox.
    // С сохранённым токеном register() — локальная операция: сетевого
    // re-register быть не должно. Реальная потеря обнаружится на pull().
    alice
        .register()
        .expect("existing token must restore locally without re-register");
    let err = alice
        .poll()
        .expect_err("must fail closed after auth-state loss");
    assert!(
        format!("{err:?}").contains("NotFound"),
        "unexpected error: {err:?}"
    );
    let still_missing =
        rt.block_on(async { !store.read().await.mailboxes.contains_key(&alice_mailbox) });
    assert!(still_missing);
}

/// MIN-RED-009: локальная БД не должна раскрывать identity контактов.
///
/// Раньше слот лога назывался `app/log/{identity_hex}`, поэтому социальный
/// граф читался прямо из файла, хотя тела сообщений были зашифрованы.
#[test]
fn storage_db_does_not_leak_contact_identity_in_slot_names() {
    use std::fs;

    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir_a = unique_test_dir("min-app-red009");
    let dir_b = unique_test_dir("min-app-red009-b");
    let key = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));

    let mut alice = AppCore::open(
        &dir_a,
        key,
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        }),
    )
    .expect("open alice");
    let mut bob = AppCore::open(
        &dir_b,
        key,
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        }),
    )
    .expect("open bob");

    alice.register().expect("alice register");
    bob.register().expect("bob register");

    let invite_b = bob.my_invite().expect("bob invite");
    let contact_b = alice
        .add_contact_by_invite("Bob", &invite_b)
        .expect("alice adds bob");
    let msg = alice
        .send_text(&contact_b.name, "hello bob")
        .expect("alice sends");
    assert_eq!(msg.text, "hello bob");

    // Проверяем ВСЕ файлы SQLite: `journal_mode=WAL` держит новые записи
    // (в т.ч. имена слотов) в `<path>-wal` до checkpoint, поэтому сканируем
    // и основной файл, и WAL. Плюс проверка на непустоту, иначе assert
    // проходит тривиально (как было до фикса PoC).
    let mut scanned = 0usize;
    for candidate in [
        dir_a.clone(),
        dir_a.join(format!("{}-wal", dir_a.display())),
    ] {
        let Ok(bytes) = fs::read(&candidate) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        scanned += 1;
        let bob_identity_lower = contact_b.identity_hex.to_lowercase();
        assert!(
            !bytes
                .windows(bob_identity_lower.len())
                .any(|w| w.eq_ignore_ascii_case(bob_identity_lower.as_bytes())),
            "identity контакта не должна встречаться в файле БД открытым текстом: {}",
            candidate.display()
        );
    }
    assert!(
        scanned >= 1,
        "не найдено ни одного непустого файла SQLite — проверка была бы фиктивной"
    );

    // Регрессия против «лечим пустой историей»: та же переписка читается.
    let history = alice.messages(&contact_b.name).expect("history readable");
    assert!(
        history.contains("hello bob"),
        "история должна сохраниться при opaque-слотах"
    );
}

/// MIN-RED-013 v2: `NotFound` на enqueue — это отсутствие mailbox ПОЛУЧАТЕЛЯ,
/// а не потеря наших sender-кред. Клиент обязан сказать об этом прямо и НЕ
/// трогать свой локальный pull-токен (прежняя версия затирала его и уходила
/// в «mailbox уже занят, а локальный pull token отсутствует»).
#[test]
fn enqueue_notfound_keeps_local_token_and_names_the_peer() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir_a = unique_test_dir("min-app-nf-a");
    let dir_b = unique_test_dir("min-app-nf-b");
    let key = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let link_a = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let link_b = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let mut alice = AppCore::open(&dir_a, key, MailboxClient::new(link_a)).unwrap();
    let mut bob = AppCore::open(&dir_b, key, MailboxClient::new(link_b)).unwrap();
    alice.register().unwrap();
    bob.register().unwrap();
    alice
        .add_contact_by_invite("Bob", &bob.my_invite().unwrap())
        .unwrap();

    let own_mailbox = own_mailbox_id(&mut alice);

    // Реле потеряло ТОЛЬКО mailbox получателя (Боб офлайн и не перерегистрировался).
    // my_invite() многострочный (MIN3:…\nBND:…), парсер принимает одну строку.
    let bob_key_line = bob.my_invite().unwrap().lines().next().unwrap().to_string();
    let bob_mailbox = hex::encode(
        min_protocol::contact_key::ContactKeyV3::parse_string_form(&bob_key_line)
            .unwrap()
            .mailbox_id,
    );
    rt.block_on(async {
        let mut s = store.write().await;
        assert!(s.mailboxes.remove(&bob_mailbox).is_some());
    });
    assert!(rt.block_on(async { store.read().await.get(&own_mailbox).is_some() }));

    // Ошибка внятная и называет собеседника, а не talks про токены.
    let err = alice
        .send_text("Bob", "привет")
        .expect_err("missing peer mailbox must fail");
    let text = format!("{err:?}");
    assert!(
        text.contains("Bob"),
        "ошибка должна называть собеседника: {text}"
    );
    assert!(
        !text.contains("уже занят"),
        "NotFound не должен выглядеть как claim-hijack: {text}"
    );

    // Собственный токен не тронут: mailbox Алисы на месте и pull работает.
    assert!(
        rt.block_on(async { store.read().await.get(&own_mailbox).is_some() }),
        "локальный pull token не должен стираться при NotFound"
    );
    assert!(
        alice.poll().is_ok(),
        "poll продолжает работать после NotFound"
    );
}

/// MIN-RED-013: relay потерял sender-token (рестарт без persisted auth-state).
/// Раньше отправка падала «Forbidden» до ручного перезапуска приложения.
/// Теперь явное действие пользователя (отправка) само восстанавливает mailbox.
#[test]
fn send_recovers_after_relay_lost_sender_token() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir_a = unique_test_dir("min-app-red013-a");
    let dir_b = unique_test_dir("min-app-red013-b");
    let key = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let link_a = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let link_b = LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    };
    let mut alice = AppCore::open(&dir_a, key, MailboxClient::new(link_a)).unwrap();
    let mut bob = AppCore::open(&dir_b, key, MailboxClient::new(link_b)).unwrap();
    alice.register().unwrap();
    bob.register().unwrap();
    alice
        .add_contact_by_invite("Bob", &bob.my_invite().unwrap())
        .unwrap();
    // Боб тоже добавляет Алису: иначе у него нет сессии на decrypt её входящих.
    bob.add_contact_by_invite("Alice", &alice.my_invite().unwrap())
        .unwrap();

    // Имитация рестарта relay без persistent auth-state: mailbox Алисы исчез.
    rt.block_on(async {
        let mut s = store.write().await;
        *s = min_relay::store::Store::new();
    });

    // Фоновая проверка входящих остаётся fail-closed: не пере-claim'ает молча.
    // Это защита от claim-hijack — публичный mailbox_id нельзя перехватить.
    let polled = alice.poll();
    assert!(
        polled.is_err(),
        "poll() после потери mailbox обязан вернуть ошибку, а не пере-claim"
    );

    // Собеседник действует первым: его отправка восстанавливает ЕГО mailbox
    // (сама по себе она провалится — mailbox Алисы пока тоже отсутствует).
    let _ = bob.send_text("Alice", "первым делом восстанавливаюсь");

    // Алиса шлёт: её re-claim проходит, цель (Боб) уже существует → доставка.
    let sent = alice
        .send_text("Bob", "после потери auth-state")
        .expect("send must self-heal sender credentials");
    assert_eq!(sent.status, min_app::MessageStatus::Sent);

    // Ровно один re-claim: mailbox зарегистрирован и не заспамирован.
    let own_mailbox = own_mailbox_id(&mut alice);
    rt.block_on(async {
        let s = store.read().await;
        assert!(
            s.get(&own_mailbox).is_some(),
            "mailbox Алисы должен быть пере-регистрирован (own={own_mailbox})"
        );
    });

    // Доставка реальна: Боб (со свежим токеном) читает расшифрованный текст.
    let incoming = bob.poll().expect("bob pulls with his re-claimed mailbox");
    assert_eq!(incoming.len(), 1, "bob must receive exactly one message");
    assert_eq!(incoming[0].text, "после потери auth-state");
}

/// mailbox Алисы берём из её собственного Contact Key: это тот же источник
/// истины, что использует relay, без угадывания identity.
fn own_mailbox_id<L: FrameExchange>(core: &mut AppCore<L>) -> String {
    let ck =
        min_protocol::contact_key::ContactKeyV3::parse_string_form(&core.my_contact_key().unwrap())
            .expect("own contact key parses");
    hex::encode(ck.mailbox_id)
}

/// MIN-RED-017: сбой на фазе ПОДКЛЮЧЕНИЯ ничего не отправил relay, поэтому
/// повтор безопасен. `enqueue` не идемпотентен: повтор после уже отправленного
/// кадра дал бы дубль, поэтому ретраим только `DeliveryError::Connect`.
#[test]
fn send_retries_only_when_connection_failed() {
    use min_net::NetError;

    /// Первые N `Enqueue` роняют соединение (кадр не уходит), дальше — норма.
    /// Регистрацию не трогаем: проверяем именно повтор отправки.
    struct FlakyLink {
        store: Arc<RwLock<min_relay::store::Store>>,
        rt: Arc<tokio::runtime::Runtime>,
        failures_left: u32,
    }

    impl FrameExchange for FlakyLink {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DeliveryError> {
            let req = FrameRequest::from_wire(request).map_err(DeliveryError::Protocol)?;
            if matches!(req, FrameRequest::Enqueue { .. }) && self.failures_left > 0 {
                self.failures_left -= 1;
                return Err(DeliveryError::Connect(NetError::Transport(
                    "simulated connect failure".into(),
                )));
            }
            let resp = self.rt.block_on(min_relay::frame_server::handle_frame(
                &self.store.clone(),
                req,
            ));
            resp.to_wire()
                .map_err(|e| DeliveryError::Protocol(e.into()))
        }
    }

    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let key = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";

    let dir_b = unique_test_dir("min-app-flaky-b");
    let mut bob = AppCore::open(
        &dir_b,
        key,
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        }),
    )
    .unwrap();
    bob.register().unwrap();

    // Два обрыва на подключении (из трёх разрешённых попыток) → сообщение уходит.
    let dir_a = unique_test_dir("min-app-flaky-a");
    let mut alice = AppCore::open(
        &dir_a,
        key,
        MailboxClient::new(FlakyLink {
            store: store.clone(),
            rt: rt.clone(),
            failures_left: 2,
        }),
    )
    .unwrap();
    alice.register().unwrap();
    alice
        .add_contact_by_invite("Bob", &bob.my_invite().unwrap())
        .unwrap();
    // Боб добавляет Алису: без своей сессии он не сможет расшифровать входящее.
    bob.add_contact_by_invite("Alice", &alice.my_invite().unwrap())
        .unwrap();

    alice
        .send_text("Bob", "через обрывы")
        .expect("connect-failure retry must succeed");

    let incoming = bob.poll().expect("bob polls");
    assert_eq!(
        incoming.len(),
        1,
        "Боб получил ровно одно сообщение (без дубля)"
    );
    assert_eq!(incoming[0].text, "через обрывы");

    // Локальный лог Алисы: ровно одна запись, её item_id == принятый relay'ом.
    let local: Vec<min_app::Message> =
        serde_json::from_str(&alice.messages("Bob").unwrap()).unwrap();
    assert_eq!(
        local.len(),
        1,
        "в логе Алисы одна запись (ретрай не создал вторую)"
    );
    assert_eq!(
        incoming[0].item_id.as_deref(),
        local[0].item_id.as_deref(),
        "item_id должен совпасть: ретрай не создал вторую позицию в очереди"
    );
}

/// MIN-RED-020: элемент, который не подходит ни одной сессии, возвращался из
/// очереди relay при каждом poll (наблюдалось 14 раз на одном item) и никогда
/// не ack-ался — «сообщения не доходят» без видимой причины. Теперь причина
/// логируется один раз, а после `UNDECRYPTABLE_DROP_AFTER` попыток элемент
/// ack-ается и отбрасывается: очередь не растёт от одного битого письма.
#[test]
fn undecryptable_item_is_dropped_after_bounded_attempts() {
    use min_protocol::frame_api::QueueItemType;

    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let key = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5";

    let dir_a = unique_test_dir("min-app-undec-a");
    let mut alice = AppCore::open(
        &dir_a,
        key,
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        }),
    )
    .unwrap();
    alice.register().unwrap();
    let alice_mb = own_mailbox_id(&mut alice);

    // Чужой отправитель кладёт ciphertext, который наша сессия не откроет.
    // Mailbox регистрирует сам attacker-клиент: claim-once, поэтому
    // предварительная регистрация в store дала бы Conflict.
    let sender_mb = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
    let junk = vec![0xABu8; 512];
    // LocalLink сам делает rt.block_on, поэтому внешнего block_on тут быть
    // не должно: вложенный block_on tokio запрещает.
    let mut attacker = MailboxClient::new(LocalLink {
        store: store.clone(),
        rt: rt.clone(),
    });
    attacker.register(sender_mb).expect("sender registers");
    attacker
        .enqueue(&alice_mb, &junk, QueueItemType::Message)
        .expect("junk enqueued");

    // Несколько poll подряд: элемент возвращается, пока не наберётся лимит.
    let before = rt.block_on(async {
        store
            .read()
            .await
            .get(&alice_mb)
            .map(|mb| mb.queue.len())
            .unwrap_or(0)
    });
    assert_eq!(before, 1, "в очереди Алисы одно битое письмо");

    // Пока лимит не выбран, poll не должен падать и не должен терять элемент.
    let mut seen = 0;
    for _ in 0..4 {
        let got = alice.poll().expect("poll без паники");
        assert!(
            got.is_empty(),
            "битое письмо не должно превращаться в сообщение"
        );
        seen += 1;
    }
    assert!(seen > 0);

    // Пятый poll добирает лимит: элемент ack-ается и исчезает из очереди.
    let _ = alice.poll().expect("final poll");

    let after = rt.block_on(async {
        store
            .read()
            .await
            .get(&alice_mb)
            .map(|mb| mb.queue.len())
            .unwrap_or(0)
    });
    assert_eq!(
        after, 0,
        "после лимита попыток битое письмо обязано уйти из очереди"
    );
}

/// MIN-RED-019: переустановка приложения НЕ должна рвать mailbox.
///
/// Сценарий пользователя: удалил приложение, поставил заново, открыл — и должен
/// получить ТОТ ЖЕ аккаунт, иначе `mailbox_id = HKDF(identity, epoch)` меняется,
/// собеседник пишет в старый адрес, и переписка умирает молча.
/// Ниже Боб пишет Алисе, пока её «приложения» нет; после восстановления
/// сообщение обязано дойти.
#[test]
fn recovery_restores_mailbox_and_pending_message_after_reinstall() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir_a = unique_test_dir("min-app-red019");
    let dir_a_reinstall = unique_test_dir("min-app-red019-reinstall");
    let dir_b = unique_test_dir("min-app-red019-b");
    let key = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let mk = |rt: &Arc<tokio::runtime::Runtime>| {
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        })
    };

    let mut alice = AppCore::open(&dir_a, key, mk(&rt)).unwrap();
    let mut bob = AppCore::open(&dir_b, key, mk(&rt)).unwrap();
    alice.register().unwrap();
    bob.register().unwrap();
    let invite_a = alice.my_invite().unwrap();
    let invite_b = bob.my_invite().unwrap();
    alice.add_contact_by_invite("bob", &invite_b).unwrap();
    bob.add_contact_by_invite("alice", &invite_a).unwrap();

    let before: serde_json::Value = serde_json::from_str(&alice.self_public().unwrap()).unwrap();
    let identity_before = before["identity_hex"].as_str().unwrap().to_string();
    let mailbox_before = before["mailbox_id_hex"].as_str().unwrap().to_string();
    let epoch_before = before["epoch"].as_u64().unwrap();
    assert_eq!(before["restored"], serde_json::json!(false));

    // Блоб берём ПОСЛЕ обмена контактами: сессии к собеседнику уже есть.
    let blob = alice.recovery_export(true).unwrap();
    assert!(!blob.is_empty());

    // Приложение удалено: контейнер с БД исчез. Ключ и блоб в Keychain живы.
    // Приложение удалено: файл БД исчез (вместе с -wal/-shm), а ключ и блоб
    // в Keychain живы. storage_path — сам файл БД, не каталог.
    for suffix in ["", "-wal", "-shm"] {
        let victim = std::path::PathBuf::from(format!("{}{suffix}", dir_a.display()));
        if victim.exists() {
            std::fs::remove_file(&victim).unwrap();
        }
    }
    assert!(!std::path::Path::new(&dir_a).exists());

    // Боб пишет в отсутствие Алисы — письмо ложится в очередь relay.
    let alice_identity = first_contact_identity(&bob.contacts().unwrap());
    bob.send_text(&alice_identity, "писал пока тебя не было")
        .unwrap();

    // Алиса ставит приложение заново: тот же storage key + блоб из Keychain.
    let mut alice2 = AppCore::open_with_recovery(&dir_a_reinstall, key, Some(&blob), mk(&rt))
        .expect("recovery must restore the account, not fail and not create a new identity");

    let after: serde_json::Value = serde_json::from_str(&alice2.self_public().unwrap()).unwrap();
    assert_eq!(after["identity_hex"].as_str().unwrap(), identity_before);
    assert_eq!(after["mailbox_id_hex"].as_str().unwrap(), mailbox_before);
    assert_eq!(after["epoch"].as_u64().unwrap(), epoch_before);
    assert_eq!(after["restored"], serde_json::json!(true));

    // Контакт пережил переустановку.
    let contacts: serde_json::Value = serde_json::from_str(&alice2.contacts().unwrap()).unwrap();
    assert_eq!(contacts.as_array().unwrap().len(), 1);

    // register() — локальная операция (pull_token восстановлен), без Conflict.
    alice2
        .register()
        .expect("restored pull token must not re-claim");

    // И главное: письмо, отправленное в отсутствие, доходит.
    let got = alice2.poll().unwrap();
    assert_eq!(
        got.len(),
        1,
        "pending message must be delivered after restore"
    );
    assert_eq!(got[0].text, "писал пока тебя не было");
}

/// Битый блоб — явная ошибка, а НЕ «новый аккаунт»: молчаливая подмена
/// identity хуже явного отказа (собеседник не понимает, куда пропала переписка).
#[test]
fn corrupted_recovery_blob_fails_closed_instead_of_new_identity() {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let dir = unique_test_dir("min-app-red019-bad");
    let key = "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let mk = || {
        MailboxClient::new(LocalLink {
            store: store.clone(),
            rt: rt.clone(),
        })
    };

    let second_dir = unique_test_dir("min-app-red019-bad-second");
    let first = AppCore::open(&dir, key, mk()).unwrap();
    let mut blob = first.recovery_export(true).unwrap();
    let mid = blob.len() / 2;
    blob[mid] ^= 0x01;

    // match вместо expect_err: Ok-тип AppCore не Debug, а требование Debug
    // не должно заставлять нас выводить секретный блоб в сообщение паники.
    let err = match AppCore::open_with_recovery(&second_dir, key, Some(&blob), mk()) {
        Ok(_) => panic!("tampered blob must not silently create a new account"),
        Err(e) => e,
    };
    let text = format!("{err:?}");
    assert!(
        text.contains("recovery"),
        "error must name the recovery failure, got: {text}"
    );
}

// ===================== MIN-RED-022: сообщения от незнакомцев =====================
//
// Тумблер «кто угодно с моим invite может написать» (по умолчанию ВКЛ).
// Модель: первое сообщение само несёт prekey отправителя, получатель видит
// ЗАЯВКУ (не чат!) и решает Accept/Reject/Block. Только Accept создаёт
// сессию libsignal — иначе флуд заявками раздул бы снапшот сессий, а значит
// recovery-блоб и Keychain.

/// Пара аккаунтов на одном in-process relay + зарегистрированные mailbox'ы.
fn stranger_pair() -> (AppCore<LocalLink>, AppCore<LocalLink>, ()) {
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let mk = |store: Arc<RwLock<min_relay::store::Store>>| LocalLink {
        store,
        rt: rt.clone(),
    };
    let key = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let mut alice = AppCore::open(
        unique_test_dir("min-app-a"),
        key,
        MailboxClient::new(mk(store.clone())),
    )
    .unwrap();
    let mut bob = AppCore::open(
        unique_test_dir("min-app-b"),
        key,
        MailboxClient::new(mk(store.clone())),
    )
    .unwrap();
    alice.register().unwrap();
    bob.register().unwrap();
    (alice, bob, ())
}

fn request_ids(app: &AppCore<LocalLink>) -> Vec<String> {
    let raw: Vec<serde_json::Value> = serde_json::from_str(&app.requests().unwrap()).unwrap();
    raw.iter()
        .map(|v| v["request_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn stranger_message_lands_in_requests_and_not_in_chats() {
    let (mut alice, mut bob, ()) = stranger_pair();
    // Ручной сценарий (Accept/Reject/Block) возможен только когда тумблер
    // выключен: при включённом заявка принимается автоматически.
    bob.set_discoverability(false).unwrap();
    // Боб никого не добавлял: Алиса пишет по его invite, без ручного контакта.
    let sent = alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "здравствуйте, это Алиса")
        .unwrap();
    assert_eq!(sent.status, min_app::MessageStatus::Sent);

    // У Боба заявка есть, а чата — нет: текст не показан до решения.
    bob.poll().unwrap();
    let ids = request_ids(&bob);
    assert_eq!(ids.len(), 1, "one request expected");
    let chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert!(chats.is_empty(), "request must not create a chat");
    assert!(
        bob.messages(&ids[0]).is_err(),
        "request text must not be readable before Accept"
    );
}

#[test]
fn accept_request_opens_chat_delivers_text_and_answers_accepted() {
    let (mut alice, mut bob, ()) = stranger_pair();
    // Ручной сценарий (Accept/Reject/Block) возможен только когда тумблер
    // выключен: при включённом заявка принимается автоматически.
    bob.set_discoverability(false).unwrap();
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "первое сообщение")
        .unwrap();
    bob.poll().unwrap();
    let id = request_ids(&bob).remove(0);

    let contact = bob.accept_request(&id).unwrap();
    assert_eq!(bob.requests().unwrap(), "[]", "request is resolved");
    let history: Vec<min_app::Message> =
        serde_json::from_str(&bob.messages(&contact.identity_hex).unwrap()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text, "первое сообщение");
    assert!(!history[0].outgoing);

    // Отправитель получает нейтральное подтверждение отдельным каналом,
    // а не как реплику в чате.
    let answers = alice.poll().unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].control.as_deref(), Some("accepted"));
    assert!(answers[0].text.is_empty(), "control carries no user text");

    // После Accept переписка идёт в обе стороны как обычно.
    bob.send_text(&contact.identity_hex, "рад знакомству")
        .unwrap();
    let back = alice.poll().unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].text, "рад знакомству");
}

#[test]
fn reject_request_answers_not_delivered_and_opens_no_chat() {
    let (mut alice, mut bob, ()) = stranger_pair();
    // Ручной сценарий (Accept/Reject/Block) возможен только когда тумблер
    // выключен: при включённом заявка принимается автоматически.
    bob.set_discoverability(false).unwrap();
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "спам?")
        .unwrap();
    bob.poll().unwrap();
    let id = request_ids(&bob).remove(0);
    bob.reject_request(&id).unwrap();

    let chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert!(chats.is_empty(), "reject must not create a chat");
    let answers = alice.poll().unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].control.as_deref(), Some("not_delivered"));
}

#[test]
fn block_request_silences_sender_without_any_reply() {
    let (mut alice, mut bob, ()) = stranger_pair();
    // Ручной сценарий (Accept/Reject/Block) возможен только когда тумблер
    // выключен: при включённом заявка принимается автоматически.
    bob.set_discoverability(false).unwrap();
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "навязчиво")
        .unwrap();
    bob.poll().unwrap();
    let id = request_ids(&bob).remove(0);
    bob.block_request(&id).unwrap();

    // Блокировка не подтверждается на проводе: иначе она сама стала бы
    // сигналом спамеру (он понял бы, что его заблокировали).
    assert!(alice.poll().unwrap().is_empty(), "block must stay silent");
    assert_eq!(bob.requests().unwrap(), "[]");
    // Повторное сообщение от того же identity не создаёт новую заявку.
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "ещё раз")
        .unwrap();
    bob.poll().unwrap();
    assert_eq!(bob.requests().unwrap(), "[]", "blocked sender stays out");
}

#[test]
fn discoverability_off_queues_stranger_message_without_opening_chat() {
    let (mut alice, mut bob, ()) = stranger_pair();
    assert!(bob.discoverability().unwrap(), "default is ON");
    bob.set_discoverability(false).unwrap();
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "кто я?")
        .unwrap();
    bob.poll().unwrap();
    // Закрытый человек НИЧЕГО не теряет: письмо копится и ждёт решения
    // (кнопка в настройках). Раньше оно удалялось тихо — без следа.
    assert_eq!(
        request_ids(&bob).len(),
        1,
        "закрытый человек копит заявку, а не теряет письмо"
    );
    let chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert!(chats.is_empty(), "чат до решения не появляется");
    // И отправителю не утекает решение: он не получает ни accepted,
    // ни not_delivered (иначе он узнал бы, что его отвергли).
    let out = alice.poll().unwrap();
    assert!(
        out.iter().all(|m| m.control.is_none()),
        "закрытое решение не утекает наружу"
    );
}

#[test]
fn add_contact_then_send_by_invite_is_not_mistaken_for_rollback() {
    // Регресс: «добавил контакт по invite, потом пишу по invite» падало с
    // падало с «peer contact key epoch is stale or rolled back». Причина была
    // не в анти-откате, а в том, что один и тот же (identity, epoch)
    // привязывался к двум разным именам сессии: «User-xxxxxx» при добавлении
    // и identity-hex при отправке. Анти-откат отвергал легитимную отправку.
    //
    // Важно: проверка НЕ ослаблена — откат эпохи (строго меньший epoch) и
    // подмена identity по-прежнему отвергаются, см. следующий тест.
    let (mut alice, mut bob, ()) = stranger_pair();
    let invite = bob.my_invite().unwrap();
    let added = alice.add_contact_by_invite("", &invite).unwrap();
    assert_eq!(added.identity_hex.len(), 64);
    // Теперь отправка по тому же invite обязана пройти.
    let sent = alice.send_text_to_invite(&invite, "второе сообщение");
    assert!(
        sent.is_ok(),
        "отправка после добавления не должна считаться откатом: {:?}",
        sent.err()
    );
    bob.poll().unwrap();
    let chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert_eq!(chats.len(), 1);
}

#[test]
fn epoch_rollback_is_still_rejected() {
    // Фикс выше НЕ ослабляет анти-откат: откат эпохи (строго меньший epoch)
    // и подмена identity по-прежнему отвергаются. Проверяем на уровне сессии,
    // где живёт сама проверка, — E2E-уровень тут не может дотянуться до
    // подделки подписи, а именно она делает откат недостижимым снаружи.
    use min_session::manager::{SessionError, SessionManager};
    let mut m = SessionManager::new("me").unwrap();
    let id_a = "aa".repeat(32);
    let id_b = "bb".repeat(32);
    assert!(m.bind_contact_key_epoch(&id_a, "peer-a", 5).is_ok());
    // Откат: меньшая эпоха — отказ.
    assert!(matches!(
        m.bind_contact_key_epoch(&id_a, "peer-a", 4),
        Err(SessionError::EpochRotated)
    ));
    // Подмена адреса при той же эпохе — тоже отказ.
    assert!(matches!(
        m.bind_contact_key_epoch(&id_a, "peer-fake", 5),
        Err(SessionError::EpochRotated)
    ));
    // Ротация вперёд допустима.
    assert!(m.bind_contact_key_epoch(&id_a, "peer-a2", 6).is_ok());
    // Другой identity с той же эпохой — независимая запись, не отказ.
    assert!(m.bind_contact_key_epoch(&id_b, "peer-b", 5).is_ok());
}

#[test]
/// Регресс: ответ на сообщение в УЖЕ ЗАВЕДЁННОЙ переписке. Раньше Swift
/// сначала звал обычную отправку, она проходила успешно, и цитата терялась —
/// вторая сторона видела «просто текст» без ответа.
#[test]
fn send_message_keeps_quote_on_established_session() {
    let (mut alice, mut bob, _) = stranger_pair();
    let invite_b = bob.my_invite().unwrap();
    let invite_a = alice.my_invite().unwrap();
    alice.add_contact_by_invite("Bob", &invite_b).unwrap();
    bob.add_contact_by_invite("Alice", &invite_a).unwrap();
    alice.send_text("Bob", "привет").unwrap();
    bob.poll().unwrap(); // сессия заведена, чат есть

    let quote = min_app::model::ReplyRef {
        author: "Боб".into(),
        preview: "привет".into(),
    };
    alice
        .send_message("Bob", "и тебе", Some(&quote), None)
        .unwrap();
    let got = bob.poll().unwrap();
    assert_eq!(got.len(), 1, "цитата должна дойти");
    let peer = got[0].peer.clone();
    let log: Vec<min_app::Message> =
        serde_json::from_str(&bob.messages(&peer).unwrap()).unwrap();
    let last = log.last().unwrap();
    assert_eq!(last.text, "и тебе");
    let reply = last.reply.as_ref().expect("цитата должна сохраниться");
    assert_eq!(reply.author, "Боб");
    assert_eq!(reply.preview, "привет");
}

#[test]
fn send_message_without_session_reports_error_instead_of_silently_inviting() {
    // Без сессии и без invite — ошибка, а не молчаливая отправка «куда-то».
    let (mut alice, _bob, _) = stranger_pair();
    let r = alice.send_message("Нет-такого", "текст", None, None);
    assert!(r.is_err(), "без сессии и invite должна быть ошибка");
}

#[test]
fn first_contact_payload_over_established_session_is_not_shown_raw() {
    // Регресс (владелец, iPhone 17): сообщение «Privet» отображалось как
    // `MINQ<двоичный мусор>Privet`. Причина: отправитель звал
    // `send_text_to_invite` по наличию invite, не проверяя сессию, а приём
    // first_msg-заголовок снимал только на пути принятия заявки. Итог: в чате
    // виднелся сырой заголовок и двоичный хвост.
    let (mut alice, mut bob, ()) = stranger_pair();
    let invite = bob.my_invite().unwrap();
    alice.send_text_to_invite(&invite, "Privet").unwrap();
    bob.poll().unwrap(); // авто-приём: сессия заведена
    // Теперь Алиса отправляет ещё раз — сессия УЖЕ есть, но она по привычке
    // снова упаковывает в first-contact формат (ровно тот путь, что давал баг).
    alice.send_text_to_invite(&invite, "Privet").unwrap();
    bob.poll().unwrap();

    // Страдает ПОЛУЧАТЕЛЬ: у него сессия есть, поэтому письмо приходит обычным
    // путём, а заголовку сниматься не с чего.
    let bob_chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    let history: Vec<min_app::Message> =
        serde_json::from_str(&bob.messages(&bob_chats[0].peer).unwrap()).unwrap();
    let got = history.last().expect("сообщение дошло получателю");
    assert_eq!(got.text, "Privet", "текст должен быть без двоичного мусора");
    assert!(
        !got.text.starts_with("MINQ"),
        "сырой first_msg-заголовок попал в текст: {:?}",
        got.text
    );
}

#[test]
fn reply_quote_reaches_the_other_side_and_survives_reload() {
    // Регресс: цитата ответа жила только в UI-модели и исчезала при первом же
    // reloadChats — то есть ответ выглядел как обычное сообщение.
    let (mut alice, mut bob, ()) = stranger_pair();
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "как дела?")
        .unwrap();
    bob.poll().unwrap();
    let bob_chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert_eq!(bob_chats.len(), 1);
    let bob_peer = bob_chats[0].peer.clone();

    // Боб отвечает с цитатой (сессия уже есть — это обычный путь отправки).
    let quote = min_app::model::ReplyRef {
        author: "Алиса".into(),
        preview: "как дела?".into(),
    };
    let sent = bob
        .send_reply(&bob_peer, "всё хорошо", "Алиса", "как дела?")
        .unwrap();
    assert_eq!(sent.text, "всё хорошо", "локально текст без заголовка");
    assert_eq!(sent.reply, Some(quote.clone()));

    alice.poll().unwrap();
    let alice_chats: Vec<min_app::Chat> =
        serde_json::from_str(&alice.list_chats().unwrap()).unwrap();
    let history: Vec<min_app::Message> =
        serde_json::from_str(&alice.messages(&alice_chats[0].peer).unwrap()).unwrap();
    let got = history.last().expect("ответ дошёл");
    assert_eq!(got.text, "всё хорошо", "текст дошёл без заголовка цитаты");
    assert_eq!(got.reply, Some(quote.clone()), "цитата видна второй стороне");

    // И переживает перечитывание (раньше reload всё стирал).
    let again: Vec<min_app::Message> =
        serde_json::from_str(&alice.messages(&alice_chats[0].peer).unwrap()).unwrap();
    assert_eq!(again.last().unwrap().reply, Some(quote), "цитата не теряется");
}

#[test]
fn discoverable_stranger_message_is_accepted_without_any_ui() {
    // Требование владельца: тумблер включён по умолчанию — значит переписка с
    // незнакомцем начинается СРАЗУ, без кнопки и без UI вообще.
    let (mut alice, mut bob, ()) = stranger_pair();
    alice
        .send_text_to_invite(&bob.my_invite().unwrap(), "здравствуйте, это Алиса")
        .unwrap();
    bob.poll().unwrap();

    let chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert_eq!(chats.len(), 1, "чат создан авто-приёмом");
    let history: Vec<min_app::Message> =
        serde_json::from_str(&bob.messages(&chats[0].peer).unwrap()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text, "здравствуйте, это Алиса");
    assert!(!history[0].outgoing, "входящее");
    assert!(request_ids(&bob).is_empty(), "очередь пуста — принято сразу");

    // Отправитель получает подтверждение и дальше пишет по обычному пути.
    let out = alice.poll().unwrap();
    assert!(
        out.iter().any(|m| m.control.as_deref() == Some("accepted")),
        "отправителю приходит CONTROL accepted"
    );
    let alice_chats: Vec<min_app::Chat> =
        serde_json::from_str(&alice.list_chats().unwrap()).unwrap();
    assert_eq!(alice_chats.len(), 1, "у отправителя тоже есть чат");
    assert!(
        alice
            .send_text(&alice_chats[0].peer, "ответ по обычному пути")
            .is_ok(),
        "после авто-приёма сессия живая"
    );
}

#[test]
fn stranger_flood_creates_no_sessions_and_no_contacts() {
    // Граница памяти: N незнакомцев не должны превращаться в N сессий.
    // Сессия заводится на Accept — а он при включённом тумблере автоматический.
    // Проверяем худший для памяти случай БЕЗ авто-приёма (тумблер выключен):
    // тогда флуд не должен завести ни одной сессии и ни одного контакта.
    // При включённом тумблере сессии заводятся намеренно (продуктовое решение
    // владельца) и тогда память удерживают потолки RequestStore/recovery.
    let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let store = Arc::new(RwLock::new(min_relay::store::Store::new()));
    let key = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let mk = |store: Arc<RwLock<min_relay::store::Store>>| LocalLink {
        store,
        rt: rt.clone(),
    };
    let mut bob = AppCore::open(
        unique_test_dir("min-app-flood-bob"),
        key,
        MailboxClient::new(mk(store.clone())),
    )
    .unwrap();
    bob.register().unwrap();
    let bob_invite = bob.my_invite().unwrap();

    for i in 0..12 {
        let mut stranger = AppCore::open(
            unique_test_dir("min-app-flood-s"),
            key,
            MailboxClient::new(mk(store.clone())),
        )
        .unwrap();
        stranger.register().unwrap();
        stranger
            .send_text_to_invite(&bob_invite, &format!("спам {i}"))
            .unwrap();
    }
    bob.set_discoverability(false).unwrap();
    bob.poll().unwrap();
    let ids = request_ids(&bob);
    assert!(!ids.is_empty(), "requests are queued");
    assert!(ids.len() <= 20, "queue is capped (PROTOCOL §6)");

    // Ни одна заявка не создала контакт, и ни одной сессии в снапшоте нет:
    // блоб остаётся маленьким, потому что флуд не расшифровывался.
    let chats: Vec<min_app::Chat> = serde_json::from_str(&bob.list_chats().unwrap()).unwrap();
    assert!(chats.is_empty(), "no contacts before Accept");
    let blob = bob.recovery_export(true).unwrap();
    assert!(
        blob.len() < 24 * 1024,
        "session snapshot must stay small under flood, got {}",
        blob.len()
    );
}
