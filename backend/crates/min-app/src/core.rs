//! Ядро приложения: связывает identity, сессии (PQXDH), delivery и storage.
//!
//! Транспорт абстрагирован трейтом `FrameExchange` (min-delivery): прод —
//! Tor через FFI, тесты — in-process ссылка на store relay'а.

use crate::error::{AppError, AppResult};
use crate::model::{Chat, Contact, ContactState, Message, MessageStatus, ReplyRef};
use min_delivery::{DeliveryError, FrameExchange, MailboxClient};
use min_identity::IdentityKeypair;
use min_protocol::frame_api::FrameError;
use min_request::store::{PendingRequest, RequestStore};
use min_session::manager::SessionManager;
use min_storage::Storage;
use std::path::Path;

/// Ключи локального хранилища (пространство имён app/*).
const K_IDENTITY: &str = "app/identity_sk";
const K_PREKEY: &str = "app/signed_prekey";
const K_SESSION: &str = "app/session_snapshot";
const K_SELF: &str = "app/self";
const K_CONTACTS: &str = "app/contacts";
const K_LOG_PREFIX: &str = "app/log/";

/// Время (unix-сек) — единая точка для всех записей лога.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Повтор при сбое ПОДКЛЮЧЕНИЯ (кадр не отправлен → дубль невозможен).
///
/// `enqueue` не идемпотентен, поэтому повторяем ТОЛЬКО `DeliveryError::Connect`:
/// сбой после записи кадра может означать, что relay уже принял сообщение.
const CONNECT_RETRY_DELAYS_MS: [u64; 3] = [1_000, 3_000, 8_000];

/// Сколько раз нерасшифровываемый item терпимо возвращается из очереди relay,
/// прежде чем мы его ack-нём и отбросим (MIN-RED-020).
///
/// Бесконечное «принеси то же самое» — это и UX-ловушка, и DoS-вектор: один
/// недоставленный элемент держал бы poll-цикл и тратил трафик каждые 20 с.
const UNDECRYPTABLE_DROP_AFTER: u32 = 5;

/// Слот настройки «кто может мне писать» (MIN-RED-022, тумблер).
/// По умолчанию РАЗРЕШЕНО: MVP-требование — «любой, у кого есть мой invite,
/// может написать». Выключается пользователем через `set_discoverability`.
const K_DISCOVERABILITY: &str = "app/discoverability";
/// Карта отметок «прочитано» (peer → unix-время) одной записью: в БД их иначе
/// пришлось бы перечислять префиксным сканом, а чатов всего до 200.
const K_READ_MAP: &str = "chat/read_map";

/// Локальный потолок числа принятых контактов.
///
/// Сессия на каждого принятого незнакомца попадает в снапшот → recovery-блоб →
/// Keychain (лимит 48 КиБ). Без предела флуд приглашениями раздул бы блоб за
/// лимиты и обрушил бы восстановление аккаунта. Это НЕ ограничение приватности
/// и не «лимит сообщений» — это защита от DoS по памяти.
const MAX_ACCEPTED_CONTACTS: usize = 200;

/// Ядро приложения. Дженерик по транспорту (прод — Tor, тесты — локальная ссылка).
pub struct AppCore<L: FrameExchange> {
    identity: IdentityKeypair,
    epoch: u64,
    mailbox_id_hex: String,
    signed_prekey_hex: String,
    /// Токен pull'а (register claim-once; None = ещё не регистрировали).
    pull_token: Option<[u8; 32]>,
    /// MAC-ключ снапшота сессий (выводится из storage key, не равен ему).
    mac_key: [u8; 32],
    sessions: SessionManager,
    storage: Storage,
    client: MailboxClient<L>,
    /// Неудачные попытки расшифровки по item_id (MIN-RED-020): элемент, который
    /// не подходит ни одной сессии, не должен возвращаться из очереди вечно.
    undecryptable: std::collections::HashMap<String, u32>,
    /// MIN-RED-019: аккаунт восстановлен из блоба, а не создан заново.
    /// UI показывает это честно, без «нового аккаунта» у старого собеседника.
    restored: bool,
}

impl<L: FrameExchange> AppCore<L> {
    /// Открывает аккаунт. Recovery-блоб не принимается: для восстановления
    /// после переустановки используйте `open_with_recovery`.
    pub fn open(
        storage_path: impl AsRef<Path>,
        storage_key_hex: &str,
        client: MailboxClient<L>,
    ) -> AppResult<Self> {
        Self::open_with_recovery(storage_path, storage_key_hex, None, client)
    }

    /// Открывает (или создаёт) аккаунт из зашифрованного хранилища.
    ///
    /// `recovery_blob` — блоб из `recovery_export()` (MIN-RED-019), сырые байты. Если БД
    /// пуста, а блоб расшифровывается, identity ВОССТАНАВЛИВАЕТСЯ вместо
    /// генерации новой: mailbox_id остаётся прежним, и собеседник не
    /// перестаёт нам писать. Битый/чужой блоб — явная ошибка, НЕ «новый
    /// аккаунт»: молчаливая подмена identity хуже явного отказа.
    pub fn open_with_recovery(
        storage_path: impl AsRef<Path>,
        storage_key_hex: &str,
        recovery_blob: Option<&[u8]>,
        client: MailboxClient<L>,
    ) -> AppResult<Self> {
        let key = Self::parse_key(storage_key_hex)?;
        let mac_key = Self::mac_key(&key)?;
        let storage = Storage::open(storage_path.as_ref(), &key)?;

        let (identity, epoch, mailbox_hex, prekey_hex, local_name) =
            match storage.get(K_IDENTITY).map_err(AppError::from)? {
                Some(sk_hex) => {
                    let sk = Self::parse_key(&String::from_utf8_lossy(&sk_hex))?;
                    let kp = IdentityKeypair::from_secret_bytes(&sk);
                    let self_json = storage
                        .get(K_SELF)
                        .map_err(AppError::from)?
                        .map(|v| String::from_utf8_lossy(&v).to_string())
                        .unwrap_or_default();
                    let (epoch, mailbox_hex, prekey_hex) = Self::parse_self_json(&self_json)?;
                    let local_name = hex::encode(kp.public());
                    (kp, epoch, mailbox_hex, prekey_hex, local_name)
                }
                None => {
                    // MIN-RED-019: контейнер удалён, но блоб в Keychain есть —
                    // восстанавливаем identity вместо генерации новой.
                    if let Some(blob) = recovery_blob.filter(|b| !b.is_empty()) {
                        let p = crate::recovery::open(blob, &mac_key).map_err(AppError::Storage)?;
                        let kp = IdentityKeypair::from_secret_bytes(&p.identity_sk);
                        // Связка не просто переносится, а ПРОВЕРЯЕТСЯ: блоб мог
                        // быть собран из полей разных поколений ключа.
                        if min_identity::mailbox_id(&kp.public(), p.epoch) != p.mailbox_id {
                            return Err(AppError::Storage(
                                "recovery: mailbox_id не соответствует identity/эпохе".into(),
                            ));
                        }
                        let mailbox_hex = hex::encode(p.mailbox_id);
                        let prekey_hex = hex::encode(p.signed_prekey);
                        let self_json = Self::make_self_json(p.epoch, &mailbox_hex, &prekey_hex);
                        storage
                            .put(K_IDENTITY, &p.identity_sk)
                            .map_err(AppError::from)?;
                        storage
                            .put(K_SELF, self_json.as_bytes())
                            .map_err(AppError::from)?;
                        storage
                            .put(K_PREKEY, &p.signed_prekey)
                            .map_err(AppError::from)?;
                        if !p.bundle.is_empty() {
                            // Бандл обязан быть связан с этой identity (RED-001),
                            // иначе подставляем чужой prekey — проверяем при
                            // первом использовании my_bundle_hex().
                            storage
                                .put("app/bundle", &p.bundle)
                                .map_err(AppError::from)?;
                        }
                        if !p.pull_token.is_empty() {
                            // Сырыми байтами: `register()` читает ровно 32 байта
                            // через try_from, hex-текст не подошёл бы.
                            if p.pull_token.len() != 32 {
                                return Err(AppError::Storage(
                                    "recovery: pull token должен быть 32 байта".into(),
                                ));
                            }
                            storage
                                .put("app/pull_token", &p.pull_token)
                                .map_err(AppError::from)?;
                        }
                        if !p.session_snapshot.is_empty() {
                            // Сырыми байтами: `SessionManager::restore` проверяет
                            // MAC над ними, а не над их hex-текстом.
                            storage
                                .put(K_SESSION, &p.session_snapshot)
                                .map_err(AppError::from)?;
                        }
                        if !p.contacts.is_empty() {
                            storage
                                .put(K_CONTACTS, serde_json::to_vec(&p.contacts)?.as_slice())
                                .map_err(AppError::from)?;
                        }
                        let local_name = hex::encode(kp.public());
                        eprintln!(
                            "[min-app] account restored from recovery blob (mailbox {}…)",
                            &mailbox_hex[..6.min(mailbox_hex.len())]
                        );
                        return Self::finish_open(
                            storage_path,
                            key,
                            mac_key,
                            kp,
                            p.epoch,
                            mailbox_hex,
                            prekey_hex,
                            local_name,
                            storage,
                            client,
                            true,
                        );
                    }
                    let kp = IdentityKeypair::generate();
                    let epoch = min_identity::EPOCH_INITIAL;
                    let mailbox = min_identity::mailbox_id(&kp.public(), epoch);
                    let prekey = min_identity::SignedPrekey::generate();
                    let mailbox_hex = hex::encode(mailbox);
                    let prekey_hex = hex::encode(prekey.public());
                    let local_name = hex::encode(kp.public());
                    let self_json = Self::make_self_json(epoch, &mailbox_hex, &prekey_hex);
                    // Храним секрет hex-строкой: при чтении декодируем hex
                    // (raw-байты терялись при from_utf8_lossy).
                    let sk_hex = hex::encode(kp.secret_bytes());
                    storage
                        .put(K_IDENTITY, sk_hex.as_bytes())
                        .map_err(AppError::from)?;
                    storage
                        .put(K_SELF, self_json.as_bytes())
                        .map_err(AppError::from)?;
                    storage
                        .put(K_PREKEY, prekey_hex.as_bytes())
                        .map_err(AppError::from)?;
                    (kp, epoch, mailbox_hex, prekey_hex, local_name)
                }
            };

        Self::finish_open(
            storage_path,
            key,
            mac_key,
            identity,
            epoch,
            mailbox_hex,
            prekey_hex,
            local_name,
            storage,
            client,
            false,
        )
    }

    /// Общая сборка `AppCore` после определения identity (новая или
    /// восстановленная). Вынесено, чтобы путь восстановления и путь создания
    /// отличались ТОЛЬКО источником identity, а не всем состоянием сразу.
    #[allow(clippy::too_many_arguments)]
    fn finish_open(
        storage_path: impl AsRef<Path>,
        _key: [u8; 32],
        mac_key: [u8; 32],
        identity: IdentityKeypair,
        epoch: u64,
        mailbox_hex: String,
        prekey_hex: String,
        local_name: String,
        storage: Storage,
        client: MailboxClient<L>,
        restored: bool,
    ) -> AppResult<Self> {
        let _ = storage_path;
        let sessions = match storage.get(K_SESSION).map_err(AppError::from)? {
            Some(blob) => SessionManager::restore(&local_name, &blob, &mac_key)?,
            None => SessionManager::new(&local_name)?,
        };

        let pull_token = storage
            .get("app/pull_token")
            .map_err(AppError::from)?
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());

        Ok(Self {
            identity,
            epoch,
            mailbox_id_hex: mailbox_hex,
            signed_prekey_hex: prekey_hex,
            pull_token,
            mac_key,
            sessions,
            storage,
            client,
            undecryptable: std::collections::HashMap::new(),
            restored,
        })
    }

    // ---------------- Аккаунт / профиль ----------------

    /// Публичные данные аккаунта для UI (JSON). Ничего секретного нет:
    /// public key и mailbox_id — это и есть «визитка» (Contact Key отдельно).
    pub fn self_public(&self) -> AppResult<String> {
        Ok(serde_json::json!({
            "identity_hex": hex::encode(self.identity.public()),
            "mailbox_id_hex": self.mailbox_id_hex,
            "epoch": self.epoch,
            "restored": self.restored,
        })
        .to_string())
    }

    /// Recovery-блоб личности (MIN-RED-019) — hex, зашифрован ключом из
    /// `mac_key`. Живёт в iOS Keychain, который переживает удаление приложения.
    ///
    /// Истории сообщений здесь нет и быть не может: она под отдельным AEAD, и её
    /// бэкап означал бы «вся переписка зашифрована ключом из Keychain» —
    /// ухудшение модели угроз ради удобства.
    ///
    /// Блоб НИКОГДА не должен попадать в лог: внутри приватный ключ identity.
    ///
    /// `with_session = false` — сокращённый вариант без снапшота ratchet и
    /// prekey bundle: Keychain отказывает на крупных items, а снапшот растёт
    /// вместе с числом сессий. Сокращённый всё равно хранит адрес (identity,
    /// эпоха, mailbox, pull_token, контакты), поэтому при нехватке места
    /// выбирается ухудшение, а не отказ от recovery.
    pub fn recovery_export(&self, with_session: bool) -> AppResult<Vec<u8>> {
        let mailbox: [u8; 16] = hex::decode(&self.mailbox_id_hex)?
            .try_into()
            .map_err(|_| AppError::Protocol("bad mailbox len".into()))?;
        let prekey: [u8; 32] = hex::decode(&self.signed_prekey_hex)?
            .try_into()
            .map_err(|_| AppError::Protocol("bad prekey len".into()))?;
        let payload = crate::recovery::RecoveryPayload {
            version: crate::recovery::RECOVERY_VERSION,
            identity_sk: self.identity.secret_bytes(),
            epoch: self.epoch,
            mailbox_id: mailbox,
            signed_prekey: prekey,
            // Бандл и снапшот берутся СЫРЫМИ байтами: в v1 они лежали
            // hex-текстом и удваивали объём блоба вдвое.
            bundle: if with_session {
                self.storage.get("app/bundle")?.unwrap_or_default()
            } else {
                Vec::new()
            },
            pull_token: self.pull_token.map(|t| t.to_vec()).unwrap_or_default(),
            session_snapshot: if with_session {
                self.storage.get(K_SESSION)?.unwrap_or_default()
            } else {
                Vec::new()
            },
            contacts: self.load_contacts()?,
        };
        crate::recovery::seal(&payload, &self.mac_key).map_err(AppError::Storage)
    }

    /// Contact Key v3 строкой (MIN3:...). Подписан identity — это «визитка».
    /// Сначала гарантирует, что опубликованный bundle уже существует и содержит
    /// binding к этой identity; иначе старый локальный prekey мог бы уйти в CK.
    pub fn my_contact_key(&mut self) -> AppResult<String> {
        self.my_bundle_hex()?;
        use min_protocol::contact_key::ContactKeyV3;
        let identity_pub: [u8; 32] = self.identity.public();
        let mailbox: [u8; 16] = hex::decode(&self.mailbox_id_hex)?
            .try_into()
            .map_err(|_| AppError::Protocol("bad mailbox len".into()))?;
        let prekey: [u8; 32] = hex::decode(&self.signed_prekey_hex)?
            .try_into()
            .map_err(|_| AppError::Protocol("bad prekey len".into()))?;
        let ck = ContactKeyV3 {
            identity_public_key: identity_pub,
            mailbox_id: mailbox,
            signed_prekey_public: prekey,
            expiry: 0,
            epoch: self.epoch,
            signature: [0u8; 64],
        };
        let payload = ck.canonical_payload();
        let sig = self.identity.sign(&payload);
        let signed = ContactKeyV3 {
            signature: sig,
            ..ck
        };
        signed.verify()?;
        Ok(signed.to_string_form())
    }

    /// PreKey bundle (hex CBOR) — передаётся вместе с Contact Key.
    /// Один bundle на эпоху: генерируем один раз и храним (стабильность адреса).
    pub fn my_bundle_hex(&mut self) -> AppResult<String> {
        if let Some(stored) = self.storage.get("app/bundle")? {
            let stored_hex = String::from_utf8_lossy(&stored).to_string();
            let bundle =
                min_session::manager::PreKeyBundleData::from_cbor(&hex::decode(&stored_hex)?)?;
            if bundle.contact_key_binding.is_some() {
                if !bundle.verify_contact_key_binding(&self.identity.public()) {
                    return Err(AppError::Protocol(
                        "stored prekey bundle binding is invalid".into(),
                    ));
                }
                self.sync_signed_prekey(&bundle)?;
                return Ok(stored_hex);
            }
            // Legacy blob has no proof that these prekeys belonged to this identity.
            // Never bless it by signing it now; fall through and replace it with a
            // freshly generated bundle.
        }
        let mut bundle = self.sessions.generate_prekey_bundle()?;
        bundle.bind_contact_key(&self.identity.secret_bytes())?;
        let hex_str = hex::encode(bundle.to_cbor()?);
        self.storage
            .put("app/bundle", hex_str.as_bytes())
            .map_err(AppError::from)?;
        // Contact Key's signed-prekey must be the same prekey as the bundle.
        self.sync_signed_prekey(&bundle)?;
        Ok(hex_str)
    }

    /// Copies the libsignal signed-prekey from the authenticated bundle into
    /// the local Contact Key storage field.
    fn sync_signed_prekey(
        &mut self,
        bundle: &min_session::manager::PreKeyBundleData,
    ) -> AppResult<()> {
        let mut signed_prekey = [0u8; 32];
        signed_prekey.copy_from_slice(
            bundle
                .signed_pre_key_public
                .get(1..33)
                .ok_or_else(|| AppError::Protocol("bad libsignal signed prekey".into()))?,
        );
        self.storage
            .put(K_PREKEY, hex::encode(signed_prekey).as_bytes())
            .map_err(AppError::from)?;
        self.signed_prekey_hex = hex::encode(signed_prekey);
        Ok(())
    }

    // ---------------- Контакты ----------------

    /// Список контактов (JSON-массив).
    pub fn contacts(&self) -> AppResult<String> {
        let list = self.load_contacts()?;
        Ok(serde_json::to_string(&list)?)
    }

    fn load_contacts(&self) -> AppResult<Vec<Contact>> {
        let raw = self.storage.get(K_CONTACTS)?.unwrap_or_default();
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_slice(&raw)?)
    }

    fn save_contacts(&mut self, list: &[Contact]) -> AppResult<()> {
        self.storage
            .put(K_CONTACTS, serde_json::to_vec(list)?.as_slice())
            .map_err(AppError::from)
    }

    /// Моё приглашение (MVP-альфа): Contact Key + prekey bundle одним текстом.
    /// Формат: строка MIN3:..., затем строка BND:<hex bundle>.
    pub fn my_invite(&mut self) -> AppResult<String> {
        let mut out = self.my_contact_key()?;
        out.push(10u8 as char);
        out.push_str("BND:");
        out.push_str(&self.my_bundle_hex()?);
        Ok(out)
    }

    /// Добавляет контакт из текста приглашения (my_invite другой стороны).
    pub fn add_contact_by_invite(&mut self, name: &str, invite: &str) -> AppResult<Contact> {
        let mut lines = invite.lines().map(str::trim).filter(|l| !l.is_empty());
        let key_line = lines
            .next()
            .ok_or_else(|| AppError::Protocol("empty invite".into()))?;
        let bundle_line = lines
            .next()
            .ok_or_else(|| AppError::Protocol("invite missing BND line".into()))?;
        let bundle_hex = bundle_line
            .strip_prefix("BND:")
            .ok_or_else(|| AppError::Protocol("BND prefix missing".into()))?;
        self.add_contact(name, key_line, bundle_hex)
    }

    /// Добавляет контакт по Contact Key + bundle. Session привязывается к эпохе
    /// (init_session_with_contact_key) — подмена ключа/откат эпохи отвергается.
    pub fn add_contact(
        &mut self,
        name: &str,
        contact_key_str: &str,
        bundle_hex: &str,
    ) -> AppResult<Contact> {
        let ck = min_protocol::contact_key::ContactKeyV3::parse_string_form(contact_key_str)?;
        ck.verify()?;
        let identity_hex = hex::encode(ck.identity_public_key);
        let mailbox_hex = hex::encode(ck.mailbox_id);
        // Пустое имя — генерируем из identity ("User-XXXXXX"): безымянные
        // контакты («Contact») неразличимы в find_contact и ломают отправку
        // при втором добавленном контакте.
        let name = if name.trim().is_empty() {
            format!("User-{}", &identity_hex[..6])
        } else {
            name.to_string()
        };
        if bundle_hex.len() > min_session::MAX_PREKEY_BUNDLE_HEX {
            return Err(AppError::Protocol("prekey bundle is too large".into()));
        }
        let bundle = min_session::manager::PreKeyBundleData::from_cbor(&hex::decode(bundle_hex)?)?;
        if !bundle.verify_contact_key_binding(&ck.identity_public_key) {
            return Err(AppError::Protocol(
                "prekey bundle is not bound to the Contact Key identity".into(),
            ));
        }
        let mut bundle_spk = [0u8; 32];
        bundle_spk.copy_from_slice(
            bundle
                .signed_pre_key_public
                .get(1..33)
                .ok_or_else(|| AppError::Protocol("bad libsignal signed prekey".into()))?,
        );
        if bundle_spk != ck.signed_prekey_public {
            return Err(AppError::Protocol(
                "prekey bundle signed prekey does not match Contact Key".into(),
            ));
        }
        // Каноническое имя сессии — identity hex, а НЕ локальное имя контакта
        // («User-xxxxxx»): именно его возвращает accept_from_stranger и по
        // нему же ищется сессия при шифровании (session_key_for). Раньше здесь
        // передавалось `name`, из-за чего один и тот же (identity, epoch)
        // привязывался к двум разным именам — и при добавлении контакта, и при
        // отправке по invite. Анти-откат видел «та же эпоха, но другой адрес»
        // и отвергал ЛЕГИТИМНУЮ отправку как откат ключа (MIN-RED-022).
        self.sessions
            .init_session_with_contact_key(&identity_hex, &identity_hex, ck.epoch, &bundle)?;
        self.save_state()?;
        let contact = Contact {
            name,
            identity_hex: identity_hex.clone(),
            mailbox_id_hex: mailbox_hex,
            epoch: ck.epoch,
            state: ContactState::Accepted,
        };
        let mut list = self.load_contacts()?;
        list.retain(|c| c.identity_hex != identity_hex);
        list.push(contact.clone());
        self.save_contacts(&list)?;
        Ok(contact)
    }

    fn find_contact(&self, name_or_identity: &str) -> AppResult<Contact> {
        let list = self.load_contacts()?;
        list.iter()
            .find(|c| c.name == name_or_identity || c.identity_hex == name_or_identity)
            .cloned()
            .ok_or_else(|| AppError::ContactNotFound(name_or_identity.into()))
    }

    // ---------------- Relay: register / send / poll ----------------

    /// Регистрирует mailbox на relay и восстанавливает локальный pull-токен.
    ///
    /// В проде relay сохраняет auth-state (`mailbox_id + hash(pull_token)`) на
    /// диске, поэтому после рестарта сохранённый токен продолжает работать.
    /// Если токен уже есть, НИКОГДА не отправляем Register повторно: mailbox_id
    /// публичен, а потерянный relay-state не должен приводить к claim-hijack.
    /// Новый аккаунт без токена регистрируется ровно один раз.
    pub fn register(&mut self) -> AppResult<()> {
        let stored = self
            .storage
            .get("app/pull_token")?
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
        if let Some(token) = stored {
            // Инвариант (PROTOCOL §10 anti-hijack): с сохранённым токеном
            // register() — ЛОКАЛЬНАЯ операция. Мы НЕ пере-claim публичный
            // mailbox молча: mailbox_id выводится из identity, и тот, кто
            // зарегистрирует его первым после потери server state, получает
            // чужой pull_token. Поэтому сетевой re-register делает только
            // ЯВНЫЙ путь восстановления — send_text (действие пользователя).
            self.pull_token = Some(token);
            self.client
                .set_sender_credentials(&self.mailbox_id_hex, token);
            return Ok(());
        }

        // SOCKS-линк мог удерживать TCP-соединение к перезапущенному relay.
        // Первая попытка закрывает его, вторая уже открывает свежий stream.
        for attempt in 0..2 {
            match self.client.register(&self.mailbox_id_hex) {
                Ok((_epoch, token)) => {
                    self.storage
                        .put("app/pull_token", &token)
                        .map_err(AppError::from)?;
                    self.pull_token = Some(token);
                    // RED-013: без этого enqueue() отвергает запрос как
                    // Malformed, и СВЕЖАЯ установка вообще не может слать.
                    self.client
                        .set_sender_credentials(&self.mailbox_id_hex, token);
                    return Ok(());
                }
                Err(DeliveryError::Relay(FrameError::Conflict)) => {
                    return Err(AppError::Delivery(
                        "relay: mailbox уже занят, а локальный pull token отсутствует".into(),
                    ));
                }
                Err(_error) if attempt == 0 => {
                    eprintln!("[min-app] mailbox register attempt 1 failed; reconnecting");
                }
                Err(error) => return Err(error.into()),
            }
        }
        unreachable!("register loop returns on success or final error")
    }

    /// ЯВНЫЙ сетевой re-claim своего mailbox (RED-013 recovery). Только из
    /// send_text и только когда relay отверг sender-token; фоновый poll()
    /// re-claim не делает.
    ///
    /// Локальный токен НЕ стирается заранее: при `Conflict` (mailbox пережил
    /// рестарт и достался кому-то другому) прежняя версия теряла последний
    /// валидный токен и уходила в «mailbox занят, pull token отсутствует».
    /// Меняем состояние только после подтверждения сервера.
    fn reclaim_own_mailbox(&mut self) -> AppResult<()> {
        match self.client.register(&self.mailbox_id_hex) {
            Ok((_epoch, token)) => {
                self.storage
                    .put("app/pull_token", &token)
                    .map_err(AppError::from)?;
                self.pull_token = Some(token);
                Ok(())
            }
            Err(error) => {
                // Локальный токен остаётся нетронутым: он может быть ещё
                // действителен (mailbox просто не был потерян).
                eprintln!("[min-app] re-claim rejected by relay: {error:?}");
                Err(error.into())
            }
        }
    }

    /// Enqueue с тремя обработками отказа relay и bounded-retry на сбой
    /// подключения (кадр не уходил → повтор не создаёт дубль).
    ///
    /// - `Forbidden` — relay отверг НАШ sender-token (mailbox потерян после
    ///   рестарта реле). Лечится одним сетевым re-claim, и только тут: фоновая
    ///   операция никогда не перерегистрирует mailbox.
    /// - `NotFound` — mailbox ПОЛУЧАТЕЛЯ не зарегистрирован: собеседник ещё не
    ///   появился на этом relay. Молча «лечить» нечего, сообщаем честно.
    fn enqueue_retrying_connect(
        &mut self,
        target_mailbox: &str,
        peer_label: &str,
        ciphertext: &[u8],
        kind: min_protocol::frame_api::QueueItemType,
    ) -> AppResult<(String, u64)> {
        let mut attempt = 0usize;
        loop {
            let result = self.client.enqueue(target_mailbox, ciphertext, kind);
            let err = match result {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            match err {
                DeliveryError::Relay(FrameError::Forbidden) => {
                    eprintln!("[min-app] sender credentials rejected; re-claiming own mailbox");
                    self.reclaim_own_mailbox()?;
                    // Повтор после re-claim: креды обновились, кадр не отправлялся.
                    return Ok(self.client.enqueue(target_mailbox, ciphertext, kind)?);
                }
                DeliveryError::Relay(FrameError::NotFound) => {
                    return Err(AppError::Delivery(format!(
                        "собеседник {peer_label} ещё не появился на relay (mailbox не зарегистрирован)"
                    )));
                }
                DeliveryError::Connect(cause) if attempt < CONNECT_RETRY_DELAYS_MS.len() => {
                    let delay = CONNECT_RETRY_DELAYS_MS[attempt];
                    attempt += 1;
                    eprintln!("[min-app] connect failed ({cause}); retry #{attempt} in {delay} ms");
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
                other => return Err(other.into()),
            }
        }
    }

    /// Отправляет текст контакту. Возвращает сообщение со статусом Sent
    /// (relay принял в очередь). Ошибка сети — AppError::Delivery.
    ///
    /// `peer_name` — имя ИЛИ identity hex: резолвим через `find_contact`,
    /// дальше работаем с КАНОНИЧЕСКИМ именем записи (`contact.name`) — сессия
    /// привязана к нему (init_session_with_contact_key), иначе шифрование по
    /// identity-hex не находит сессию («core вернул NULL» в UI).
    pub fn send_text(&mut self, peer_name: &str, text: &str) -> AppResult<Message> {
        self.send_text_inner(peer_name, text, None)
    }

    /// Отправка сообщения с выбором пути ПО ФАКТУ, а не по попытке.
    ///
    /// Раньше Swift сначала звал обычную отправку и переключался на invite при
    /// ЛЮБОЙ ошибке. Это давало два дефекта:
    /// 1) цитата терялась — обычная отправка проходила успешно, и до кода с
    ///    цитатой управление уже не доходило (владелец видел «просто текст»);
    /// 2) сетевой сбой после принятия relay повторял `Enqueue` — сообщение
    ///    уходило дважды.
    ///
    /// Здесь путь выбирается по наличию сессии, цитата передаётся в любом пути,
    /// а «нет сессии» больше не маскируется сетевой ошибкой: invite — это
    /// отдельная ветка, а не запасной путь.
    pub fn send_message(
        &mut self,
        peer_name: &str,
        text: &str,
        reply: Option<&ReplyRef>,
        invite: Option<&str>,
    ) -> AppResult<Message> {
        // Сессия может быть заведена как под именем контакта (обычное
        // добавление), так и под его identity hex (заявка от незнакомца,
        // MIN-RED-022). Проверяем обе привязки, иначе заведённая переписка
        // выглядит как «нет сессии» и уходит в invite.
        let has_session = self
            .find_contact(peer_name)
            .map(|c| {
                self.sessions.has_session(&c.identity_hex) || self.sessions.has_session(&c.name)
            })
            .unwrap_or(false);
        if has_session {
            return self.send_text_inner(peer_name, text, reply);
        }
        match invite {
            Some(inv) => self.send_text_to_invite_inner(inv, text, reply),
            None => Err(AppError::Protocol("no session".into())),
        }
    }

    fn send_text_inner(
        &mut self,
        peer_name: &str,
        text: &str,
        reply: Option<&ReplyRef>,
    ) -> AppResult<Message> {
        let contact = self.find_contact(peer_name)?;
        // MIN-RED-022: сессия принятого незнакомца заведена под его identity,
        // а книга хранит имя `User-xxxxxx`. Шифровать по имени нельзя —
        // это давало бы «session not found» и молчаливую потерю переписки.
        let key = self.session_key_for(&contact);
        let ct = self
            .sessions
            .encrypt(&key, crate::reply::encode(reply, text).as_bytes())?;
        let kind = min_protocol::frame_api::QueueItemType::Message;
        // RED-013: relay отверг наш sender-token (auth-state на сервере потерян
        // при рестарте/пересборке) — пользователь видел «Forbidden» вместо
        // отправки. Восстановление инициирует ЯВНОЕ действие (эта отправка),
        // а не фоновый poll: bounded, один раз, только свой mailbox.
        let (item_id, _) =
            self.enqueue_retrying_connect(&contact.mailbox_id_hex, &contact.name, &ct, kind)?;
        self.save_state()?;
        let msg = Message {
            item_id: Some(item_id),
            peer: contact.identity_hex,
            outgoing: true,
            text: text.to_string(),
            sent_at: now_secs(),
            status: MessageStatus::Sent,
            control: None,
            reply: reply.cloned(),
        };
        self.append_message(&msg);
        Ok(msg)
    }

    /// Забирает очередь с relay: decrypt -> лог -> ack. Возвращает новые входящие.
    /// Никогда не пере-регистрирует mailbox после NotFound: mailbox_id публичен,
    /// поэтому авто-re-claim дал бы claim-hijack после потери server state.
    ///
    /// Не расшифровавшийся элемент возвращается на каждом poll. Считаем
    /// неудачные попытки по item_id: причину логируем один раз, после
    /// `UNDECRYPTABLE_DROP_AFTER` — ack и отброс, иначе один битый элемент
    /// держал бы очередь открытой навсегда.
    pub fn poll(&mut self) -> AppResult<Vec<Message>> {
        let Some(token) = self.pull_token else {
            return Err(AppError::Delivery(
                "relay: локальный pull token отсутствует; требуется явная регистрация".into(),
            ));
        };
        let items = self.client.pull(&self.mailbox_id_hex, &token)?;
        let token = self.pull_token.expect("checked above");
        let mut incoming: Vec<Message> = Vec::new();
        let mut acked_ids: Vec<String> = Vec::new();
        for item in &items {
            if let Some(msg) = self.try_decrypt_item(item) {
                self.clear_undecryptable(&item.item_id);
                incoming.push(msg);
                acked_ids.push(item.item_id.clone());
                continue;
            }
            // Не расшифровалось: различаем «сессии нет» и «сессия есть, но
            // ключ не подошёл» — это разные проблемы с разными действиями.
            // MIN-RED-022: сперва пробуем заявку от незнакомца (БЕЗ
            // расшифровки и без создания сессии). Если заявку взяли в очередь —
            // item НЕ ack'ается: письмо дождётся решения пользователя.
            // Тумблер включён (по умолчанию) — заявка принимается сразу, и
            // переписка начинается без кнопки. Выключен — заявка копится и
            // ждёт решения (кнопка в настройках).
            if let Some(msg) = self.auto_accept_item(item) {
                self.ack_items(&[item.item_id.clone()])?;
                incoming.push(msg);
                continue;
            }
            if self.offer_request(item) {
                // Конверт сохранён в RequestStore — relay-копию можно убрать.
                // Раньше item намеренно не ack'ался, из-за чего relay
                // пересылал одно и то же письмо при КАЖДОМ poll (лишний трафик
                // и рост счётчика неудачных попыток у отправителя).
                self.ack_items(&[item.item_id.clone()])?;
                self.clear_undecryptable(&item.item_id);
                continue;
            }
            let attempts = self.bump_undecryptable(&item.item_id);
            if attempts == 1 {
                let known = self.load_contacts().map(|c| !c.is_empty()).unwrap_or(false);
                let reason = if known {
                    "есть контакты, но ни одна сессия не подошла (identity собеседника \
                     изменился или это сообщение не для нас)"
                } else {
                    "нет ни одного контакта — расшифровать нечем"
                };
                eprintln!("[min-app] item {} не расшифрован: {reason}", item.item_id);
            }
            if attempts >= UNDECRYPTABLE_DROP_AFTER {
                eprintln!(
                    "[min-app] item {} отброшен после {attempts} неудачных попыток расшифровки",
                    item.item_id
                );
                self.clear_undecryptable(&item.item_id);
                acked_ids.push(item.item_id.clone());
            }
        }
        if !acked_ids.is_empty() {
            let n = self.client.ack(&self.mailbox_id_hex, &token, &acked_ids)?;
            let _ = n;
        }
        self.save_state()?;
        Ok(incoming)
    }

    /// Счётчик неудачных расшифровок по item_id (в памяти процесса: переживать
    /// перезапуск не обязательно — при новом poll очередь всё равно вернёт item).
    fn bump_undecryptable(&mut self, item_id: &str) -> u32 {
        let slot = self.undecryptable.entry(item_id.to_string()).or_insert(0);
        *slot = slot.saturating_add(1);
        *slot
    }

    fn clear_undecryptable(&mut self, item_id: &str) {
        self.undecryptable.remove(item_id);
    }

    /// Пробует расшифровать item перебором принятых контактов (сессии привязаны
    /// к имени контакта). Не расшифровалось — элемент НЕ ack'ается (остаётся).
    fn try_decrypt_item(
        &mut self,
        item: &min_protocol::frame_api::QueueItemDto,
    ) -> Option<Message> {
        let contacts = self.load_contacts().ok()?;
        let envelope = item.envelope.clone();
        for c in &contacts {
            // MIN-RED-022: сессия принятого незнакомца заведена под его
            // identity, а книга хранит имя `User-xxxxxx`. Без выбора ключа
            // `decrypt` вернул бы «нет сессии», и переписка молча терялась бы.
            let key = self.session_key_for(c);
            if let Ok(pt) = self.sessions.decrypt(&key, &envelope) {
                // CONTROL-ответ на заявку — не пользовательский текст: он идёт
                // отдельным каналом, чтобы не попасть в чат как реплика.
                let control: Option<String> = crate::ctrl::decode(&pt).map(|o| match o {
                    crate::ctrl::Outcome::Accepted => "accepted".to_string(),
                    crate::ctrl::Outcome::NotDelivered => "not_delivered".to_string(),
                });
                let text = if control.is_some() {
                    String::new()
                } else {
                    String::from_utf8_lossy(&pt).to_string()
                };
                // Первое сообщение может прийти и по УЖЕ ЗАВЕДЕННОЙ сессии:
                // отправитель зовёт `send_text_to_invite`, если у него есть
                // invite этого человека, и не проверяет, есть ли сессия. Раньше
                // приём этот заголовок не снимал, и получатель видел в чате сырой
                // `MINQ<двоичный мусор>текст`. Разбираем здесь независимо от
                // пути — это страховка, а не догадка.
                let (reply, text) = if control.is_some() {
                    (None, text)
                } else if pt.starts_with(&crate::first_msg::MAGIC[..]) {
                    match crate::first_msg::decode(&pt) {
                        Some((_, first_text)) => crate::reply::decode(first_text),
                        None => crate::reply::decode(&text),
                    }
                } else {
                    crate::reply::decode(&text)
                };
                let msg = Message {
                    item_id: Some(item.item_id.clone()),
                    peer: c.identity_hex.clone(),
                    outgoing: false,
                    text,
                    sent_at: item.arrived_at,
                    status: MessageStatus::Delivered,
                    control,
                    reply,
                };
                self.append_message(&msg);
                return Some(msg);
            }
        }
        None
    }

    // ---------------- Лог сообщений (локальный, зашифрованный storage'ом) ---

    /// MIN-RED-009: имя слота лога — opaque, а не «лог/{identity_hex}».
    ///
    /// Раньше `key` в таблице `kv` содержал identity public key контакта
    /// открытым текстом: значения (тела сообщений) шифровались, но социальный
    /// граф — список и identity всех собеседников — читался прямо из БД.
    /// Теперь слот детерминированно выводится BLAKE3 из identity с
    /// домен-разделением, поэтому:
    ///   * в БД нет ни identity, ни имён контактов;
    ///   * один и тот же контакт всегда даёт тот же слот (история не теряется);
    ///   * разные контакты не склеиваются (128 бит = BLAKE3).
    fn log_key(peer: &str) -> String {
        let digest = blake3::derive_key("min-app/log-slot/v1", peer.as_bytes());
        format!("{K_LOG_PREFIX}{}", hex::encode(&digest[..16]))
    }

    fn load_log(&self, peer: &str) -> Vec<Message> {
        match self.storage.get(&Self::log_key(peer)) {
            Ok(Some(v)) => serde_json::from_slice(&v).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn append_message(&mut self, msg: &Message) {
        let mut log = self.load_log(&msg.peer);
        log.push(msg.clone());
        if let Ok(bytes) = serde_json::to_vec(&log) {
            let _ = self.storage.put(&Self::log_key(&msg.peer), &bytes);
        }
    }

    /// История переписки с контактом (JSON-массив, хронологический порядок).
    /// до фикса, лежат в логе с первым-контактным заголовком прямо в тексте
    /// (`MINQ<28 байт>текст`), и без этого пользователь видел бы мусор в уже
    /// сохранённой переписке. Само хранилище не трогаем: заголовок снимается в
    /// ответе, поэтому чтение всегда даёт чистый текст, а данные не переписываются.
    pub fn messages(&self, peer_name_or_identity: &str) -> AppResult<String> {
        let contact = self.find_contact(peer_name_or_identity)?;
        let mut log = self.load_log(&contact.identity_hex);
        for m in log.iter_mut() {
            m.text = repair_legacy_first_contact_text(&m.text);
        }
        Ok(serde_json::to_string(&log)?)
    }

    /// Список чатов (агрегаты по контактам).
    pub fn list_chats(&self) -> AppResult<String> {
        let contacts = self.load_contacts()?;
        let mut chats: Vec<Chat> = contacts
            .iter()
            .map(|c| {
                let log = self.load_log(&c.identity_hex);
                let (last_text, last_at) = log
                    .last()
                    .map(|m| (m.text.clone(), m.sent_at))
                    .unwrap_or_default();
                Chat {
                    peer: c.identity_hex.clone(),
                    name: c.name.clone(),
                    last_text,
                    last_at,
                    unread: 0,
                }
            })
            .collect();
        chats.sort_by_key(|c| std::cmp::Reverse(c.last_at));
        Ok(serde_json::to_string(&chats)?)
    }

    // ---------------- Вспомогательные (private) ----------------

    fn parse_key(hex_str: &str) -> AppResult<[u8; 32]> {
        hex::decode(hex_str)?
            .try_into()
            .map_err(|_| AppError::Storage("bad storage key length".into()))
    }

    fn mac_key(storage_key: &[u8; 32]) -> AppResult<[u8; 32]> {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(b"min-app/session-snapshot-mac/v1");
        h.update(storage_key);
        let out = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(out.as_bytes());
        Ok(key)
    }

    fn make_self_json(epoch: u64, mailbox_hex: &str, prekey_hex: &str) -> String {
        serde_json::json!({
            "epoch": epoch,
            "mailbox_id_hex": mailbox_hex,
            "signed_prekey_hex": prekey_hex,
        })
        .to_string()
    }

    fn parse_self_json(json: &str) -> AppResult<(u64, String, String)> {
        let v: serde_json::Value = serde_json::from_str(json)?;
        let epoch = v["epoch"].as_u64().unwrap_or(min_identity::EPOCH_INITIAL);
        let mailbox = v["mailbox_id_hex"].as_str().unwrap_or_default().to_string();
        let prekey = v["signed_prekey_hex"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok((epoch, mailbox, prekey))
    }

    /// Сохраняет состояние сессий (snapshot + MAC по производному ключу).
    /// Вызывается после каждой мутации сессий: send/decrypt/add_contact.
    fn save_state(&mut self) -> AppResult<()> {
        let blob = self.sessions.snapshot(&self.mac_key)?;
        self.storage.put(K_SESSION, &blob).map_err(AppError::from)
    }
    // ================= MIN-RED-022: заявки от незнакомцев =================
    //
    // Тумблер «кто может мне писать» (K_DISCOVERABILITY) по умолчанию РАЗРЕШЁН:
    // MVP-требование — «любой, у кого есть мой invite, может написать».
    // Настройка ЛОКАЛЬНАЯ: в сеть не уходит. Иначе «я закрыт» стало бы
    // метаданными, читаемым перебором invite-кодов (см. ctrl.rs).

    /// Отметки «прочитано» для чата. Живут в зашифрованном хранилище ядра, а НЕ
    /// в Swift-кэше: кэш лежит в контейнере приложения и удаляется при
    /// переустановке, поэтому прочитанное снова выглядело бы непрочитанным.
    /// Один источник истины — ядро, там же где сама переписка.
    pub fn mark_chat_read(&mut self, peer_name: &str) -> AppResult<()> {
        let mut map = self.read_markers()?;
        map.insert(peer_name.to_owned(), now_secs());
        self.storage
            .put(K_READ_MAP, &serde_json::to_vec(&map).map_err(|e| {
                AppError::Protocol(format!("read markers serialize: {e}"))
            })?)
            .map_err(AppError::from)
    }

    /// Отметка с ЯВНЫМ временем — для миграции старых отметок. Без этого
    /// перенос записал бы «сейчас» и старые сообщения снова выглядели бы
    /// непрочитанными. Обычный `mark_chat_read` всегда использует now_secs().
    pub fn mark_chat_read_at(&mut self, peer_name: &str, at: u64) -> AppResult<()> {
        let mut map = self.read_markers()?;
        // Не затираем более свежую отметку старой (миграция бывает позже открытия).
        if map.get(peer_name).copied().unwrap_or(0) >= at {
            return Ok(());
        }
        map.insert(peer_name.to_owned(), at);
        self.storage
            .put(K_READ_MAP, &serde_json::to_vec(&map).map_err(|e| {
                AppError::Protocol(format!("read markers serialize: {e}"))
            })?)
            .map_err(AppError::from)
    }

    /// Отметки «прочитано» для UI: peer → unix-время. Отсутствие чата в карте
    /// означает «ещё не открывали», и непрочитанными считаются все входящие.
    pub fn read_markers(&self) -> AppResult<std::collections::BTreeMap<String, u64>> {
        match self.storage.get(K_READ_MAP)? {
            Some(v) => Ok(serde_json::from_slice(&v).unwrap_or_default()),
            None => Ok(Default::default()),
        }
    }

    /// Разрешены ли заявки от незнакомцев. Дефолт — `true`.
    pub fn discoverability(&self) -> AppResult<bool> {
        match self.storage.get(K_DISCOVERABILITY)? {
            Some(v) => Ok(matches!(v.as_slice(), b"1")),
            None => Ok(true),
        }
    }

    /// Переключатель «кто может мне писать». Только локально, без сети.
    pub fn set_discoverability(&mut self, allowed: bool) -> AppResult<()> {
        self.storage
            .put(K_DISCOVERABILITY, if allowed { b"1" } else { b"0" })
            .map_err(AppError::from)
    }

    /// Ключ сессии для контакта: первое существующее имя.
    ///
    /// Сессия может быть заведена под одним именем, а контакт в книге — жить
    /// под другим (принятый незнакомец заводится под hex(identity), а
    /// показывается как `User-xxxxxx`). Без этой проверки encrypt/decrypt
    /// срослись бы с «нет сессии», и переписка молча терялась бы.
    fn session_key_for(&self, c: &Contact) -> String {
        if self.sessions.has_session(&c.identity_hex) {
            c.identity_hex.clone()
        } else {
            c.name.clone()
        }
    }

    /// Имя контакта по умолчанию — детерминированно из identity, чтобы два
    /// независимых клиента дали одно и то же имя и не было коллизий.
    fn default_name(identity_hex: &str) -> String {
        let short = &identity_hex[..identity_hex.len().min(6)];
        format!("User-{short}")
    }

    /// Разбирает и ПРОВЕРЯЕТ invite: Contact Key (подпись) + bundle (binding).
    ///
    /// Единая точка доверия для `add_contact` и `send_to_invite`: обе операции
    /// обязаны отвергнуть подменённый ключ одинаково.
    fn parse_invite(
        &self,
        invite: &str,
    ) -> AppResult<(
        min_protocol::contact_key::ContactKeyV3,
        min_session::manager::PreKeyBundleData,
    )> {
        let mut lines = invite.lines().map(str::trim).filter(|l| !l.is_empty());
        let key_line = lines
            .next()
            .ok_or_else(|| AppError::Protocol("empty invite".into()))?;
        let bundle_line = lines
            .next()
            .ok_or_else(|| AppError::Protocol("invite missing BND line".into()))?;
        let bundle_hex = bundle_line
            .strip_prefix("BND:")
            .ok_or_else(|| AppError::Protocol("BND prefix missing".into()))?;

        let ck = min_protocol::contact_key::ContactKeyV3::parse_string_form(key_line)?;
        ck.verify()?;
        if bundle_hex.len() > min_session::MAX_PREKEY_BUNDLE_HEX {
            return Err(AppError::Protocol("prekey bundle is too large".into()));
        }
        let bundle = min_session::manager::PreKeyBundleData::from_cbor(&hex::decode(bundle_hex)?)?;
        // MIN-RED-001: bundle подписан identity из Contact Key. Без этой
        // проверки relay подменил бы prekey и провёл бы MITM сессии.
        if !bundle.verify_contact_key_binding(&ck.identity_public_key) {
            return Err(AppError::Protocol(
                "prekey bundle is not bound to the Contact Key identity".into(),
            ));
        }
        // Signed prekey в bundle обязан совпадать с Contact Key: подмена
        // означала бы другой комплект ключей у того же identity.
        let bundle_spk = bundle
            .signed_pre_key_public
            .get(1..33)
            .ok_or_else(|| AppError::Protocol("bad libsignal signed prekey".into()))?;
        if bundle_spk != ck.signed_prekey_public {
            return Err(AppError::Protocol(
                "prekey bundle signed prekey does not match Contact Key".into(),
            ));
        }
        Ok((ck, bundle))
    }

    // ================= MIN-RED-022: сообщения от незнакомцев =================
    //
    // Модель MVP: «кто угодно с моим invite может мне написать» (тумблер
    // `discoverability`, по умолчанию ВКЛ). Рукопожатие по шаблону Signal:
    // первое сообщение само несёт prekey отправителя, получатель заводит
    // заявку и решает Accept/Reject/Block. Ничего не показывается и не
    // попадает в чат ДО решения — иначе «принимает любой, у кого есть мой
    // invite» превратилось бы в форму для спама.
    //
    // Границы памяти (путь кормит недоверенный источник):
    //   * сессия libsignal создаётся ТОЛЬКО в accept_from_stranger, то есть по
    //     явному Accept/Reject/Block пользователя — не на каждый конверт;
    //   * в очереди заявок лежат СЫРЫЕ конверты, бюджет жёстко ограничен
    //     (min-request: 20 заявок / 4 конверта / 512 КиБ суммарно);
    //   * на Resolve сессия забывается и выпадает из снапшота (forget_peer),
    //     поэтому recovery-блоб не растёт от spam-флуда.

    /// Адрес моего mailbox'а в виде 16 байт.
    fn my_mailbox(&self) -> AppResult<[u8; 16]> {
        hex::decode(&self.mailbox_id_hex)?
            .try_into()
            .map_err(|_| AppError::Protocol("bad mailbox len".into()))
    }

    /// Отправляет ПЕРВОЕ сообщение незнакомцу по его invite — без ручного
    /// добавления в контакты. Сессия заводится сразу, текст уходит с
    /// заголовком `first_msg` (адрес+эпоха ОТПРАВИТЕЛЯ), иначе получатель не
    /// сможет ответить: в конверте (PROTOCOL §3) адреса нет, а relay их не
    /// показывает.
    /// Ответ на сообщение: цитата уезжает в зашифрованный payload, поэтому её
    /// видит вторая сторона и она переживает перезапуск. Раньше цитата жила
    /// только в UI-модели и терялась при первом reloadChats.
    pub fn send_reply(
        &mut self,
        peer_name: &str,
        text: &str,
        author: &str,
        preview: &str,
    ) -> AppResult<Message> {
        let r = ReplyRef {
            author: author.to_string(),
            preview: preview.to_string(),
        };
        self.send_text_inner(peer_name, text, Some(&r))
    }

    /// Первое сообщение незнакомцу, если это ответ (цитата едет внутри
    /// first-message payload — она зашифрована, relay её не видит).
    pub fn send_text_to_invite_reply(
        &mut self,
        invite: &str,
        text: &str,
        author: &str,
        preview: &str,
    ) -> AppResult<Message> {
        let r = ReplyRef {
            author: author.to_string(),
            preview: preview.to_string(),
        };
        self.send_text_to_invite_inner(invite, text, Some(&r))
    }

    pub fn send_text_to_invite(&mut self, invite: &str, text: &str) -> AppResult<Message> {
        self.send_text_to_invite_inner(invite, text, None)
    }

    fn send_text_to_invite_inner(
        &mut self,
        invite: &str,
        text: &str,
        reply: Option<&ReplyRef>,
    ) -> AppResult<Message> {
        let (ck, bundle) = self.parse_invite(invite)?;
        let identity_hex = hex::encode(ck.identity_public_key);
        if RequestStore::is_blocked(&self.storage, &ck.identity_public_key) {
            return Err(AppError::Protocol("contact is blocked (locally)".into()));
        }
        let name = Self::default_name(&identity_hex);
        let known = self.load_contacts()?.len() < MAX_ACCEPTED_CONTACTS
            || self.sessions.has_session(&identity_hex);
        if !known {
            return Err(AppError::Protocol("contact limit reached".into()));
        }
        if !self.sessions.has_session(&identity_hex) {
            self.sessions.init_session_with_contact_key(
                &identity_hex,
                &identity_hex,
                ck.epoch,
                &bundle,
            )?;
        }
        let payload = crate::first_msg::encode(
            &self.my_mailbox()?,
            self.epoch,
            &crate::reply::encode(reply, text),
        )
        .ok_or_else(|| AppError::Protocol("message too long for first contact".into()))?;
        let ct = self.sessions.encrypt(&identity_hex, &payload)?;
        // Тип Request: у получателя он попадает в отдельную очередь заявок
        // (PROTOCOL §6: cap 20, TTL 7 дней), а не в общую.
        let (item_id, _) = self.enqueue_retrying_connect(
            &hex::encode(ck.mailbox_id),
            &identity_hex,
            &ct,
            min_protocol::frame_api::QueueItemType::Request,
        )?;
        self.save_state()?;
        let mailbox_hex = hex::encode(ck.mailbox_id);
        self.adopt_contact(&identity_hex, &mailbox_hex, ck.epoch, name)?;
        let msg = Message {
            item_id: Some(item_id),
            peer: identity_hex,
            outgoing: true,
            text: text.to_string(),
            sent_at: now_secs(),
            status: MessageStatus::Sent,
            control: None,
            reply: reply.cloned(),
        };
        self.append_message(&msg);
        Ok(msg)
    }

    fn parse_request_id(&self, hex_str: &str) -> AppResult<[u8; 16]> {
        hex::decode(hex_str)?
            .try_into()
            .map_err(|_| AppError::Protocol("bad request id".into()))
    }

    /// Заявки от незнакомцев для UI (JSON-массив, свежие первыми).
    ///
    /// Текста заявки здесь нет: он лежит в зашифрованном конверте и читается
    /// только после Accept. Карточка в UI показывает, кто и когда прислал
    /// заявку, а текст — после принятия.
    pub fn requests(&self) -> AppResult<String> {
        let now = now_secs();
        let mut list: Vec<serde_json::Value> = RequestStore::pending(&self.storage, now)
            .iter()
            .map(|r| {
                serde_json::json!({
                    "request_id": hex::encode(r.request_id),
                    "identity_hex": hex::encode(r.peer_identity),
                    "first_seen": r.first_seen,
                    "expires_at": r.expires_at,
                    "envelopes": r.envelopes.len(),
                })
            })
            .collect();
        list.sort_by_key(|v| std::cmp::Reverse(v["first_seen"].as_u64().unwrap_or(0)));
        Ok(serde_json::to_string(&list)?)
    }

    /// Принимает заявку: сессия заводится (и только тут), отправителю уходит
    /// `Accepted`, заявка исчезает, её текст становится первым сообщением чата.
    pub fn accept_request(&mut self, request_id_hex: &str) -> AppResult<Contact> {
        let id = self.parse_request_id(request_id_hex)?;
        let now = now_secs();
        let req = RequestStore::take(&self.storage, &id, now)
            .ok_or_else(|| AppError::ContactNotFound(request_id_hex.into()))?;
        let first = req
            .envelopes
            .first()
            .cloned()
            .ok_or_else(|| AppError::Protocol("request has no envelope".into()))?;

        // Единственное место, где создаётся сессия незнакомца: здесь
        // подпись его identity проверяется внутри libsignal.
        let fc = self.sessions.accept_from_stranger(&first)?;
        if fc.peer_identity != req.peer_identity {
            // Заявленный ≠ проверенный: кто-то подделался под другую identity.
            // Молча принимать нельзя — и текст показывать тоже.
            self.sessions.forget_peer(&fc.peer_name);
            return Err(AppError::Protocol(
                "request identity does not match the verified sender".into(),
            ));
        }
        let decoded = crate::first_msg::decode(&fc.plaintext);
        let Some((header, raw_text)) = decoded else {
            self.sessions.forget_peer(&fc.peer_name);
            return Err(AppError::Protocol("not a first-contact message".into()));
        };
        // Первое сообщение может быть ответом — цитата едет внутри payload.
        let (reply, text) = crate::reply::decode(raw_text);
        let peer_mailbox_hex = hex::encode(header.sender_mailbox);

        self.reply_outcome(
            &fc.peer_name,
            &peer_mailbox_hex,
            crate::ctrl::Outcome::Accepted,
        )?;
        let contact = self.adopt_contact(
            &fc.peer_name,
            &peer_mailbox_hex,
            header.sender_epoch,
            Self::default_name(&fc.peer_name),
        )?;
        if !text.is_empty() {
            let msg = Message {
                item_id: Some(req.relay_item_id.clone()),
                peer: fc.peer_name.clone(),
                outgoing: false,
                text: text.to_string(),
                sent_at: now,
                status: MessageStatus::Delivered,
                control: None,
                reply,
            };
            self.append_message(&msg);
        }
        self.ack_items(&[req.relay_item_id])?;
        self.save_state()?;
        Ok(contact)
    }

    /// Отклоняет заявку. Отправитель получает НЕЙТРАЛЬНЫЙ `NotDelivered`:
    /// различать «отклонено» / «заблокировано» / «заявки выключены» нельзя —
    /// это выдавало бы решение получателя (см. ctrl.rs).
    pub fn reject_request(&mut self, request_id_hex: &str) -> AppResult<()> {
        self.resolve_request(request_id_hex, false)
    }

    /// Блокирует отправителя: заявки удаляются локально, в блок-лист, ответ
    /// наружу НЕ уходит (иначе блокировка сама стала бы сигналом спамеру).
    pub fn block_request(&mut self, request_id_hex: &str) -> AppResult<()> {
        self.resolve_request(request_id_hex, true)
    }

    fn resolve_request(&mut self, request_id_hex: &str, block: bool) -> AppResult<()> {
        let id = self.parse_request_id(request_id_hex)?;
        let now = now_secs();
        let req = RequestStore::take(&self.storage, &id, now)
            .ok_or_else(|| AppError::ContactNotFound(request_id_hex.into()))?;
        if block {
            RequestStore::block(&self.storage, &req.peer_identity, now);
            self.ack_items(&[req.relay_item_id])?;
            return Ok(());
        }
        // Reject: ответ уходит, поэтому сессию приходится завести. Она
        // сразу забывается — в снапшот не попадает (forget_peer).
        if let Some(first) = req.envelopes.first().cloned() {
            if let Ok(fc) = self.sessions.accept_from_stranger(&first) {
                if let Some((header, _)) = crate::first_msg::decode(&fc.plaintext) {
                    self.reply_outcome(
                        &fc.peer_name,
                        &hex::encode(header.sender_mailbox),
                        crate::ctrl::Outcome::NotDelivered,
                    )?;
                }
                self.sessions.forget_peer(&fc.peer_name);
            }
        }
        self.ack_items(&[req.relay_item_id])?;
        self.save_state()?;
        Ok(())
    }

    /// Отправляет CONTROL-ответ по уже заведённой сессии пира.
    fn reply_outcome(
        &mut self,
        peer_name: &str,
        peer_mailbox_hex: &str,
        outcome: crate::ctrl::Outcome,
    ) -> AppResult<()> {
        let payload = crate::ctrl::encode(outcome);
        let ct = self.sessions.encrypt(peer_name, &payload)?;
        // Ошибку доставки ответа глушим: это best-effort-уведомление, и его
        // отсутствие не должно ломать действие пользователя (Accept уже состоялся).
        if let Err(e) = self.enqueue_retrying_connect(
            peer_mailbox_hex,
            peer_name,
            &ct,
            min_protocol::frame_api::QueueItemType::Control,
        ) {
            eprintln!("[min-app] control reply not delivered: {e:?}");
        }
        Ok(())
    }

    /// Заводит/обновляет контакт в книге (сессия уже есть).
    fn adopt_contact(
        &mut self,
        identity_hex: &str,
        mailbox_hex: &str,
        epoch: u64,
        name: String,
    ) -> AppResult<Contact> {
        let mut list = self.load_contacts()?;
        if list.len() >= MAX_ACCEPTED_CONTACTS
            && !list.iter().any(|c| c.identity_hex == identity_hex)
        {
            return Err(AppError::Protocol("contact limit reached".into()));
        }
        let contact = Contact {
            name,
            identity_hex: identity_hex.to_string(),
            mailbox_id_hex: mailbox_hex.to_string(),
            epoch,
            state: ContactState::Accepted,
        };
        list.retain(|c| c.identity_hex != identity_hex);
        list.push(contact.clone());
        self.save_contacts(&list)?;
        Ok(contact)
    }

    /// Ack указанных item_id. Ошибка сети не критична: следующий poll вернёт
    /// те же элементы, а логика заявок идемпотентна.
    fn ack_items(&mut self, item_ids: &[String]) -> AppResult<()> {
        let Some(token) = self.pull_token else {
            return Ok(());
        };
        let real: Vec<String> = item_ids.iter().filter(|i| !i.is_empty()).cloned().collect();
        if real.is_empty() {
            return Ok(());
        }
        self.client.ack(&self.mailbox_id_hex, &token, &real)?;
        for id in real {
            self.clear_undecryptable(&id);
        }
        Ok(())
    }

    /// Кладёт входящий PreKey-конверт от незнакомца в очередь заявок.
    ///
    /// БЕЗ расшифровки: сессия на каждый конверт от недоверенного источника
    /// раздувала бы снапшот, а с ним recovery-блоб и Keychain. Расшифровка
    /// только в `auto_accept_item` / `accept_request`.
    fn auto_accept_item(
        &mut self,
        item: &min_protocol::frame_api::QueueItemDto,
    ) -> Option<Message> {
        if !self.discoverability().unwrap_or(false) {
            return None;
        }
        let identity = min_session::manager::peek_stranger_identity(&item.envelope)?;
        if RequestStore::is_blocked(&self.storage, &identity) {
            return None;
        }
        let fc = self.sessions.accept_from_stranger(&item.envelope).ok()?;
        if hex::encode(identity) != fc.peer_name {
            // Заявленный ≠ проверенный: тихо отказ, ничего не показываем.
            self.sessions.forget_peer(&fc.peer_name);
            return None;
        }
        let (header, raw_text) = crate::first_msg::decode(&fc.plaintext)?;
        let (reply, text) = crate::reply::decode(raw_text);
        let peer_mailbox_hex = hex::encode(header.sender_mailbox);
        // Контакт должен завестись ДО ответа: если исчерпан
        // MAX_ACCEPTED_CONTACTS, принимать нельзя. Иначе отправитель получил бы
        // `accepted`, решил бы, что писать ему можно, а писать ему было бы
        // нечем (в книге его нет), и в снапшоте осталась бы сессия-сирота,
        // раздувающая recovery-блоб.
        if self
            .adopt_contact(
                &fc.peer_name,
                &peer_mailbox_hex,
                header.sender_epoch,
                Self::default_name(&fc.peer_name),
            )
            .is_err()
        {
            self.sessions.forget_peer(&fc.peer_name);
            return None;
        }
        let _ = self.reply_outcome(
            &fc.peer_name,
            &peer_mailbox_hex,
            crate::ctrl::Outcome::Accepted,
        );
        let now = now_secs();
        let msg = Message {
            item_id: Some(item.item_id.clone()),
            peer: fc.peer_name.clone(),
            outgoing: false,
            text: text.to_string(),
            sent_at: now,
            status: MessageStatus::Delivered,
            control: None,
            reply,
        };
        self.append_message(&msg);
        let _ = self.save_state();
        Some(msg)
    }

    fn offer_request(&mut self, item: &min_protocol::frame_api::QueueItemDto) -> bool {
        // Тумблер НЕ влияет на то, копится ли заявка. Раньше выключенный
        // тумблер приводил к тихому удалению письма (очередь не бралась), и
        // закрывшийся человек терял сообщение навсегда без следа. Теперь
        // заявка копится всегда: тумблер решает только АВТОМАТИЧЕСКОЕ принятие
        // (см. auto_accept_item), а решение вручную — кнопка в настройках.
        let Some(identity) = min_session::manager::peek_stranger_identity(&item.envelope) else {
            return false;
        };
        let now = now_secs();
        // От блокера не копим: молча убираем, решение наружу не выдаём.
        if RequestStore::is_blocked(&self.storage, &identity) {
            let _ = self.ack_items(&[item.item_id.clone()]);
            return true;
        }
        // request_id не предсказуем (CSPRNG), иначе виден порядок прихода.
        let mut rid = [0u8; 16];
        if getrandom::getrandom(&mut rid).is_err() {
            return false;
        }
        let req = PendingRequest {
            request_id: rid,
            peer_identity: identity,
            // Адрес отправителя известен только после расшифровки (он лежит
            // ВНУТРИ plaintext). Нули — честная неизвестность, а не выдумка.
            peer_mailbox: [0u8; 16],
            epoch: 0,
            first_seen: now,
            expires_at: now.saturating_add(min_request::store::TTL_REQUEST_SEC),
            envelopes: vec![item.envelope.clone()],
            relay_item_id: item.item_id.clone(),
        };
        RequestStore::upsert(&self.storage, req, now)
    }
}

/// Возвращает текст сообщения, очищенный от первоконтактного заголовка.
///
/// Заголовок `MINQ` появился в тексте сообщений, принятых старой версией.
/// Он пишется в БД как есть, поэтому починить его можно только на чтение —
/// переписывать хранилище нельзя: запись могла бы превратиться в
/// нераспаковываемую мусорную запись при любом сбое записи.
fn repair_legacy_first_contact_text(text: &str) -> String {
    if !text.as_bytes().starts_with(&crate::first_msg::MAGIC[..]) {
        return text.to_string();
    }
    // Целый заголовок ещё на месте — снимаем точно.
    //
    // Проверка на U+FFFD обязательна: битые байты после `from_utf8_lossy`
    // хранятся как ВАЛИДНЫЙ UTF-8 (U+FFFD), поэтому структурный разбор проходит
    // успешно и молча берёт «Алису» за mailbox, а в текст просачивается хвост
    // заголовка. Заголовок с подменами — это не заголовок.
    let header_intact = {
        let end = std::cmp::min(28, text.len());
        let end = (0..end).rev().find(|&i| text.is_char_boundary(i)).unwrap_or(0);
        !text[..end].contains('\u{FFFD}')
    };
    if header_intact {
        if let Some((_, body)) = crate::first_msg::decode(text.as_bytes()) {
            let (_, body) = crate::reply::decode(body);
            return body.to_string();
        }
    }
    // Точное восстановление. `from_utf8_lossy` портит НЕ ВСЕ байты заголовка:
    // невалидные последовательности стали U+FFFD, а байты, случайно оказавшиеся
    // валидным UTF-8 (вроде `)}`), остались обычными символами. Поэтому «взять
    // хвост после последней замены» нельзя — мусор может лежать ПОСЛЕ неё.
    //
    // Зато можно посчитать байты исходного payload: валидный символ даёт свой
    // len_utf8, а каждая U+FFFD — ровно ОДИН потерянный байт. Заголовок занимает
    // ровно 4 + 16 + 8 = 28 байт, поэтому тело начинается там, где счётчик
    // переваливает за 28. Это не эвристика, а восстановление по структуре.
    // Байтовый проход — только если потеря байтов действительно была. Без
    // U+FFFD строка не тронута `from_utf8_lossy`, и любой сдвиг был бы выдумкой.
    if !text.contains('\u{FFFD}') {
        return text.to_string();
    }
    let header_len = crate::first_msg::HEADER_LEN;
    let mut orig = 0usize;
    for (idx, ch) in text.char_indices() {
        let n = if ch == '\u{FFFD}' { 1 } else { ch.len_utf8() };
        if orig + n > header_len {
            return text[idx..].to_string();
        }
        orig += n;
    }
    // Заголовок занял всю строку — тела нет, вернуть как есть.
    text.to_string()
}

/// Безопасность починки: она НЕ трогает живые тексты. Вопрос владельца —
/// «если человек просто напишет MINQ, сообщение пропадёт?» — проверяется
/// тестом, а не обещанием.
#[test]
fn repair_leaves_user_text_untouched() {
    let user_text = "MINQ это просто текст про рельсы";
    assert_eq!(repair_legacy_first_contact_text(user_text), user_text);
    let odd = "MINQ\u{FFFD} хвост";
    assert_eq!(repair_legacy_first_contact_text(odd), odd);
    assert_eq!(repair_legacy_first_contact_text("привет"), "привет");
}

/// Смесь: часть байтов заголовка стала U+FFFD, а валидные байты остались
/// символами. Именно так выглядит реально испорченная запись, и «хвост после
/// последней замены» тут даёт мусор перед текстом.
#[test]
fn repair_handles_valid_utf8_leftovers_after_replacements() {
    // 4 + 22 + 2 = 28 байт заголовка: 22 байта стали U+FFFD, а `)}` случайно
    // оказались валидным UTF-8 и остались символами.
    let lost = "\u{FFFD}".repeat(22);
    let damaged = String::from("MINQ") + &lost + ")}Privet";
    assert_eq!(repair_legacy_first_contact_text(&damaged), "Privet");
}

/// Короткий текст пользователя с `MINQ` и символом-заменой не должен терять
/// начало: до 28 исходных байт он целиком считается «заголовком» — а значит
/// возвращается как есть.
#[test]
fn repair_keeps_short_user_text_with_replacement() {
    let user = "MINQ\u{FFFD} хвост";
    assert_eq!(repair_legacy_first_contact_text(user), user);
}

/// Настоящая длина: 4 + 24 = 28 байт заголовка, тело — с 29-го.
#[test]
fn repair_recovers_text_after_lost_header_bytes() {
    let damaged = format!("MINQ{}Privet", "\u{FFFD}".repeat(24));
    assert_eq!(repair_legacy_first_contact_text(&damaged), "Privet");
    // Ровно 28 байт: тела нет — вернуть как есть, ничего не вырезать.
    let no_body = format!("MINQ{}", "\u{FFFD}".repeat(24));
    assert_eq!(repair_legacy_first_contact_text(&no_body), no_body);
    // Кириллица в теле считается по 2 байта — смещение не должно «поехать».
    let cyr = format!("MINQ{}привет", "\u{FFFD}".repeat(24));
    assert_eq!(repair_legacy_first_contact_text(&cyr), "привет");
}

/// Целый заголовок снимается точно, без эвристики.
#[test]
fn repair_strips_intact_header_exactly() {
    let payload = crate::first_msg::encode(&[9u8; 16], 3, "Privet").unwrap();
    let as_text = String::from_utf8_lossy(&payload).to_string();
    assert_eq!(repair_legacy_first_contact_text(&as_text), "Privet");
}

#[cfg(test)]
mod tests {
    use super::*;
    use min_delivery::DeliveryResult;

    struct NeverLink;
    impl FrameExchange for NeverLink {
        fn exchange(&mut self, _request: &[u8]) -> DeliveryResult<Vec<u8>> {
            unreachable!("bundle migration must not touch delivery")
        }
    }

    #[test]
    fn legacy_unbound_bundle_is_replaced_not_blind_resigned() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("min-app-legacy-bundle-{nonce}"));
        let key = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let mut app = AppCore::open(&dir, key, MailboxClient::new(NeverLink)).unwrap();

        let mut legacy = app.sessions.generate_prekey_bundle().unwrap();
        legacy.contact_key_binding = None;
        let legacy_id = legacy.pre_key_id;
        app.storage
            .put(
                "app/bundle",
                hex::encode(legacy.to_cbor().unwrap()).as_bytes(),
            )
            .unwrap();

        let replacement_hex = app.my_bundle_hex().unwrap();
        let replacement =
            min_session::PreKeyBundleData::from_cbor(&hex::decode(replacement_hex).unwrap())
                .unwrap();
        assert_ne!(replacement.pre_key_id, legacy_id);
        assert!(replacement.verify_contact_key_binding(&app.identity.public()));
    }
}
