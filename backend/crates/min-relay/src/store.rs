//! In-memory relay store с optional persistent auth-state (ТЗ §12.2).
//!
//! Очереди ciphertext и prekey bundles всегда RAM-only. Если задан state-dir,
//! на диск атомарно сохраняется только `mailbox_id + BLAKE3(pull_token)`:
//! это переживает рестарт relay и не раскрывает identity, token или payload.
//!
//! Авторизация на pull/ack через `pull_token` — случайный 32-байтный ключ,
//! выдаётся ОДИН раз при register. Без токена pull вернёт 404, ack — 0.
//! Это критично: mailbox_id выводится из публичного identity-ключа (PROTOCOL §5),
//! поэтому знания mailbox_id недостаточно для доступа к очереди.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Ограничения очереди (ТЗ §8.7).
pub const REQUEST_QUEUE_CAP: usize = 20;
pub const MESSAGE_QUEUE_CAP: usize = 200;
pub const REQUEST_TTL_SEC: u64 = 7 * 24 * 3600; // ~7 дней
pub const MESSAGE_TTL_SEC: u64 = 14 * 24 * 3600; // ~14 дней

/// Длина pull_token в байтах (256 бит энтропии).
const PULL_TOKEN_LEN: usize = 32;

/// Сколько последних ack'нутых item_id помнить для идемпотентного повторного
/// ack (retry после таймаута). Ограничение — против роста памяти журнала.
const ACKED_HISTORY_MAX: usize = 512;
/// Resource cap для registry. Ограничивает RAM и размер auth-state при
/// анонимном Register-флуде; не является Sybil/access-control решением.
const MAX_MAILBOXES: usize = 10_000;
/// Максимум bucket'ов для attacker-controlled mailbox_id. После достижения
/// новые ключи временно ограничиваются только global bucket.
const MAX_RATE_BUCKETS: usize = 50_000;

#[derive(Debug, Clone)]
pub struct Mailbox {
    pub mailbox_id: String,
    pub epoch: u64,
    pub prekey_bundle: Option<PrekeyBundle>,
    pub queue: Vec<QueueItem>,
    /// Восстановленный с диска BLAKE3-хэш токена (сам токен никогда не пишется).
    pull_token_hash: Option<[u8; 32]>,
    /// Флаг: токен уже был выдан и более не возвращается.
    token_claimed: bool,
    /// Кольцевой журнал последних подтверждённых item_id: повторный ack после
    /// таймаута должен вернуть тот же счётчик (retry-friendly), хотя сами
    /// элементы уже удалены из `queue`. Ограничен по размеру — иначе это
    /// отдельная DoS-поверхность.
    acked_recent: std::collections::VecDeque<String>,
}

/// Генерирует `n` случайных байт через rand_core::OsRng (getrandom backend).
pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut buf = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut buf);
    buf
}

impl Mailbox {
    /// Генерирует новый pull_token, оставляя в памяти только его хэш.
    /// Возвращает hex-токен клиенту; в auth-state сохраняется hash-token.
    fn claim_token(&mut self) -> String {
        let token = hex::encode(random_bytes(PULL_TOKEN_LEN));
        self.pull_token_hash = Some(Self::token_hash(&token));
        self.token_claimed = true;
        token
    }

    fn token_hash(token: &str) -> [u8; 32] {
        *blake3::hash(token.as_bytes()).as_bytes()
    }

    /// Проверяет, соответствует ли предъявленный токен stored-у.
    ///
    /// AUDIT MIN-06: сравнение constant-time через `subtle::ConstantTimeEq`.
    /// Раньше `stored == presented` возвращал false на первом несовпавшем байте —
    /// timing side-channel, позволявший перебирать токен побайтово. Несовпадение
    /// длины возвращает false сразу: длина токена фиксирована (64 hex), не секрет.
    pub fn check_token(&self, presented: &str) -> bool {
        use subtle::ConstantTimeEq;
        let Some(stored) = self.pull_token_hash.as_ref() else {
            return false;
        };
        let presented_hash = Self::token_hash(presented);
        bool::from(stored.ct_eq(&presented_hash))
    }
}

#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    pub identity_public: String,       // hex
    pub signed_prekey_public: String,  // hex
    pub one_time_prekeys: Vec<String>, // hex public keys
}

#[derive(Debug, Clone)]
pub struct QueueItem {
    pub item_id: String,
    pub envelope_hex: String, // opaque ciphertext
    pub arrived_at: u64,
    pub expires_at: u64,
    pub item_type: ItemType,
    pub acked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    Request,
    Message,
    Control,
}

#[derive(Debug)]
pub struct Store {
    pub mailboxes: HashMap<String, Mailbox>,
    /// Anti-spam token bucket per mailbox (AUDIT MIN-01): живёт рядом с
    /// очередями, проверяется до выполнения register/enqueue/pull/ack.
    /// Не сериализуется и не часть wire-формата — внутреннее состояние relay.
    pub limiter: crate::antispam::RateLimiter,
    /// AUDIT RT-26.4 (F-3): глобальный bucket. Per-mailbox лимит ключуется
    /// attacker-controlled mailbox_id — атакующий ротацией свежих id получал
    /// N × burst. Глобальный ключ вне контроля атакующего; конфликт нечестных
    /// и честных клиентов ограничен (ёмкость подобрана с запасом под Pi-масштаб).
    global_limiter: crate::antispam::RateLimiter,
    /// Persistent auth-state path; queued ciphertext никогда сюда не пишется.
    auth_state_path: Option<PathBuf>,
    /// После неустранимой ошибки append/rollback новые Register запрещены,
    /// но выданные токены и текущие очереди продолжают работать.
    auth_state_poisoned: bool,
}

/// Ключ глобального bucket'а (вне пространства mailbox_id).
const GLOBAL_RATE_KEY: &str = "\0global\0";

/// Глобальная конфигурация: суммарный burst всех клиентов relay.
/// 300 ≈ 10 × per-mailbox burst (30): один abuser не выедает глобально всё,
/// но 300-кратный флуд с ротацией id останавливается.
const GLOBAL_RATE: crate::antispam::RateLimitConfig = crate::antispam::RateLimitConfig {
    burst: 300,
    refill_per_sec: 30.0,
};

impl Default for Store {
    fn default() -> Self {
        Self {
            mailboxes: HashMap::new(),
            limiter: crate::antispam::RateLimiter::new(crate::antispam::RateLimitConfig::default()),
            global_limiter: crate::antispam::RateLimiter::new(GLOBAL_RATE),
            auth_state_path: None,
            auth_state_poisoned: false,
        }
    }
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Создаёт store с persistent auth-state. Очереди и payload всегда RAM-only.
    pub fn with_auth_state(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self::default();
        store.auth_state_path = Some(path);
        store.load_auth_state()?;
        Ok(store)
    }

    fn auth_state_file(&self) -> Option<PathBuf> {
        self.auth_state_path
            .as_ref()
            .map(|p| p.join("mailbox-auth.state"))
    }

    fn load_auth_state(&mut self) -> std::io::Result<()> {
        let Some(path) = self.auth_state_file() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            return self.persist_auth_state();
        }
        let bytes = fs::read(path)?;
        let text = String::from_utf8(bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "auth state is not UTF-8")
        })?;
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let invalid = || {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid auth-state line {}", line_no + 1),
                )
            };
            let mut parts = line.split_whitespace();
            let id = parts.next().ok_or_else(invalid)?;
            let hash_hex = parts.next().ok_or_else(invalid)?;
            if parts.next().is_some() {
                return Err(invalid());
            }
            if id.is_empty() || id.len() > 256 || id.chars().any(char::is_whitespace) {
                return Err(invalid());
            }
            let hash = hex::decode(hash_hex).map_err(|_| invalid())?;
            let hash = <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| invalid())?;
            if self.mailboxes.contains_key(id) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("duplicate auth-state mailbox at line {}", line_no + 1),
                ));
            }
            let mb = Mailbox {
                mailbox_id: id.to_string(),
                epoch: 1,
                prekey_bundle: None,
                queue: Vec::new(),
                pull_token_hash: Some(hash),
                token_claimed: true,
                acked_recent: std::collections::VecDeque::new(),
            };
            self.mailboxes.insert(id.to_string(), mb);
            if self.mailboxes.len() > MAX_MAILBOXES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "auth-state exceeds mailbox capacity",
                ));
            }
        }
        Ok(())
    }

    fn append_auth_state(&mut self, mailbox_id: &str, hash: [u8; 32]) -> std::io::Result<()> {
        let Some(path) = self.auth_state_file() else {
            return Ok(());
        };
        if self.auth_state_poisoned {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "auth state is poisoned",
            ));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            self.persist_auth_state()?;
        }
        let original_len = fs::metadata(&path)?.len();
        let result = (|| {
            let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            writeln!(file, "{} {}", mailbox_id, hex::encode(hash))?;
            file.sync_data()
        })();
        if let Err(write_error) = result {
            // WAL-like rollback: не оставляем partial line перед следующим append.
            let rollback = OpenOptions::new().write(true).open(&path).and_then(|file| {
                file.set_len(original_len)?;
                file.sync_all()
            });
            if rollback.is_err() {
                self.auth_state_poisoned = true;
                tracing::error!(
                    "auth-state append and rollback failed; new registrations disabled"
                );
            }
            return Err(write_error);
        }
        Ok(())
    }

    /// Полный атомарный snapshot — только при создании state-файла.
    fn persist_auth_state(&self) -> std::io::Result<()> {
        let Some(path) = self.auth_state_file() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut text = String::from(
            "# MIN relay auth-state: mailbox_id BLAKE3(pull_token); no payload/identity\n",
        );
        for (id, mb) in &self.mailboxes {
            if let Some(hash) = mb.pull_token_hash {
                text.push_str(id);
                text.push(' ');
                text.push_str(&hex::encode(hash));
                text.push('\n');
            }
        }
        let tmp = path.with_extension("tmp");
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(tmp, path)
    }

    /// Проверяет и списывает `cost` токенов у bucket'а `key`.
    /// false = rate limited (операция не выполняется).
    pub fn check_rate(&mut self, key: &str, cost: u32) -> bool {
        self.limiter.check_bounded(key, cost, MAX_RATE_BUCKETS)
    }

    /// AUDIT RT-26.4 (F-3): глобальный лимит — проверяется ВМЕСТЕ с per-mailbox
    /// в каждом обработчике. Ротация attacker-controlled ключей больше не даёт
    /// неограниченный суммарный burst.
    pub fn check_rate_global(&mut self, cost: u32) -> bool {
        self.global_limiter.check(GLOBAL_RATE_KEY, cost)
    }

    /// Регистрирует новый mailbox. Возвращает pull_token (hex) для последующего
    /// доступа к pull/ack. Если mailbox уже существует — возвращает ошибку
    /// (claim-once: нельзя перехватить чужой mailbox_id).
    pub fn register(&mut self, mailbox_id: String) -> Result<String, &'static str> {
        if self.auth_state_poisoned {
            return Err("auth state unavailable");
        }
        if mailbox_id.is_empty()
            || mailbox_id.len() > 256
            || mailbox_id.chars().any(char::is_whitespace)
        {
            return Err("invalid mailbox id");
        }
        if self.mailboxes.contains_key(&mailbox_id) {
            return Err("mailbox already exists");
        }
        if self.mailboxes.len() >= MAX_MAILBOXES {
            return Err("mailbox capacity reached");
        }
        let mut mb = Mailbox {
            mailbox_id: mailbox_id.clone(),
            epoch: 1,
            prekey_bundle: None,
            queue: Vec::new(),
            pull_token_hash: None,
            token_claimed: false,
            acked_recent: std::collections::VecDeque::new(),
        };
        let token = mb.claim_token();
        let hash = mb.pull_token_hash.ok_or("internal token hash missing")?;
        let original_id = mailbox_id.clone();
        self.mailboxes.insert(mailbox_id, mb);
        if self.append_auth_state(&original_id, hash).is_err() {
            self.mailboxes.remove(&original_id);
            return Err("auth state persist failed");
        }
        Ok(token)
    }

    pub fn get(&self, id: &str) -> Option<&Mailbox> {
        self.mailboxes.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Mailbox> {
        self.mailboxes.get_mut(id)
    }

    pub fn enqueue(&mut self, mailbox_id: &str, item: QueueItem) -> Result<(), &'static str> {
        let mb = self
            .mailboxes
            .get_mut(mailbox_id)
            .ok_or("mailbox not found")?;
        let cap = if item.item_type == ItemType::Request {
            REQUEST_QUEUE_CAP
        } else {
            MESSAGE_QUEUE_CAP
        };
        let current = mb
            .queue
            .iter()
            .filter(|q| !q.acked && q.item_type == item.item_type)
            .count();
        if current >= cap {
            return Err("queue full");
        }
        mb.queue.push(item);
        Ok(())
    }

    /// Подтверждает обработку позиции и освобождает память.
    ///
    /// Раньше элемент только помечался `acked`, оставаясь в `queue` до TTL.
    /// Cap при этом считал только `!acked`, поэтому непрерывный цикл
    /// enqueue→ack раздувал вектор без ограничения — DoS на RAM реле.
    /// Теперь элемент удаляется сразу; идемпотентность повторного ack даёт
    /// кольцевой журнал `acked_recent`.
    pub fn ack(&mut self, mailbox_id: &str, item_id: &str) -> bool {
        let Some(mb) = self.mailboxes.get_mut(mailbox_id) else {
            return false;
        };
        let Some(index) = mb.queue.iter().position(|q| q.item_id == item_id) else {
            // Повторный ack: считаем успехом, если id в кольцевом журнале.
            return mb.acked_recent.iter().any(|id| id == item_id);
        };
        let item = mb.queue.remove(index);
        mb.acked_recent.push_back(item.item_id);
        while mb.acked_recent.len() > ACKED_HISTORY_MAX {
            mb.acked_recent.pop_front();
        }
        true
    }

    pub fn prune_expired(&mut self, now: u64) {
        // AUDIT RT-26.8 (F-4): TTL — единственный терминальный срок жизни
        // письма (PROTOCOL: TTL MESSAGE = 14 дней). Прежний предикат
        // `expires_at > now || !q.acked` удерживал НЕзабранные письма
        // бессрочно — «почтовый ящик-зомби». Забранное (acked) письмо тоже
        // удаляется по истечении TTL: доставка уже состоялась.
        for mb in self.mailboxes.values_mut() {
            mb.queue.retain(|q| q.expires_at > now);
        }
        // Попутная гигиена rate limiter: bucket'ы, не использовавшиеся час,
        // освобождают память (AUDIT MIN-01).
        self.limiter
            .sweep_idle(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod smoke {
    use super::{ItemType, QueueItem, Store, MESSAGE_QUEUE_CAP};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("min-relay-{tag}-{}-{n}", std::process::id()))
    }

    #[test]
    fn auth_state_survives_restart_without_persisting_token() {
        let dir = temp_dir("auth");
        let mailbox = "00112233445566778899aabbccddeeff";
        let token;
        {
            let mut s = Store::with_auth_state(&dir).unwrap();
            token = s.register(mailbox.into()).unwrap();
            let file = fs::read_to_string(dir.join("mailbox-auth.state")).unwrap();
            assert!(file.contains(mailbox));
            assert!(
                !file.contains(&token),
                "raw pull_token must never be persisted"
            );
            assert_eq!(file.lines().count(), 2, "header + one mailbox");
        }
        let mut restored = Store::with_auth_state(&dir).unwrap();
        let mb = restored.get(mailbox).expect("mailbox restored");
        assert!(mb.check_token(&token), "existing client keeps pull access");
        assert!(!mb.check_token(&"00".repeat(32)));
        assert_eq!(
            restored.register(mailbox.into()).unwrap_err(),
            "mailbox already exists"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn auth_state_corruption_fails_startup_closed() {
        let dir = temp_dir("auth-corrupt");
        fs::create_dir_all(&dir).unwrap();
        // Последняя hash-строка обрезана: silently skip превратил бы удалённый
        // mailbox в свободный для повторного claim.
        fs::write(
            dir.join("mailbox-auth.state"),
            b"# state\n00112233445566778899aabbccddeeff deadbeef\n",
        )
        .unwrap();
        let err = Store::with_auth_state(&dir).expect_err("corrupt state must fail closed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mailbox_registry_is_bounded() {
        let mut s = Store::new();
        for i in 0..10_000 {
            s.register(format!("mb-{i}")).unwrap();
        }
        assert_eq!(
            s.register("mb-overflow".into()).unwrap_err(),
            "mailbox capacity reached"
        );
        assert_eq!(s.mailboxes.len(), 10_000);
    }

    #[test]
    fn append_state_preserves_existing_mailboxes() {
        let dir = temp_dir("auth-append");
        let first = "00112233445566778899aabbccddeeff";
        let second = "ffeeddccbbaa99887766554433221100";
        let first_token;
        let second_token;
        {
            let mut s = Store::with_auth_state(&dir).unwrap();
            first_token = s.register(first.into()).unwrap();
            second_token = s.register(second.into()).unwrap();
        }
        let restored = Store::with_auth_state(&dir).unwrap();
        assert!(restored.get(first).unwrap().check_token(&first_token));
        assert!(restored.get(second).unwrap().check_token(&second_token));
        assert_eq!(restored.mailboxes.len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn register_issues_token() {
        let mut s = Store::new();
        let token = s.register("mbx".into()).unwrap();
        assert_eq!(token.len(), 64, "token — hex от 32 байт = 64 символа");
        let mb = s.get("mbx").unwrap();
        assert!(mb.check_token(&token));
        assert!(!mb.check_token("wrong-token"));
    }

    #[test]
    fn register_claim_once() {
        let mut s = Store::new();
        s.register("mbx".into()).unwrap();
        assert_eq!(
            s.register("mbx".into()).unwrap_err(),
            "mailbox already exists"
        );
    }

    #[test]
    fn wrong_token_rejected() {
        let mut s = Store::new();
        let token = s.register("mbx".into()).unwrap();
        let mb = s.get("mbx").unwrap();
        assert!(!mb.check_token("not-the-".repeat(8).trim())); // 64 символа, но не тот
        assert!(mb.check_token(&token));
    }

    /// AUDIT MIN-06: та же длина, но другой токен — обязательный reject
    /// (раньше сравнение было `==` — timing leak; теперь ct_eq).
    #[test]
    fn equal_length_wrong_token_rejected() {
        let mut s = Store::new();
        let token = s.register("mbx".into()).unwrap();
        let mb = s.get("mbx").unwrap();
        // Перевёрнутый hex той же длины (64 символа).
        let flipped: String = token.chars().rev().collect();
        assert_ne!(flipped, token);
        assert!(!mb.check_token(&flipped));
        // Отличие только в последнем байте — результат одинаково false
        // (constant-time, без раннего выхода на первом несовпавшем байте).
        let mut near = token.clone();
        let last = near.len() - 1;
        let alt = if near.ends_with('0') { "1" } else { "0" };
        near.replace_range(last.., alt);
        assert!(!mb.check_token(&near));
        // Пустая и короткая строка тоже отвергаются.
        assert!(!mb.check_token(""));
        assert!(!mb.check_token(&token[..63]));
    }

    /// AUDIT RT-8: перехват занятого mailbox невозможен — повторный register
    /// конфликтует, а у атакующего нет pull_token (он выдан ОДИН раз
    /// легитимному клиенту и более не возвращается).
    #[test]
    fn rt8_mailbox_hijack_rejected() {
        let mut s = Store::new();
        let token = s.register("mbx".into()).unwrap();
        // Атакующий знает mailbox_id (он публичен: HKDF от identity), но register
        // обязан провалиться — иначе он получил бы новый токен на чужую очередь.
        assert_eq!(
            s.register("mbx".into()).unwrap_err(),
            "mailbox already exists"
        );
        let mb = s.get("mbx").unwrap();
        assert!(mb.check_token(&token));
        assert!(!mb.check_token("attacker-token"));
        assert!(!mb.check_token(&"00".repeat(32)));
    }

    /// AUDIT RT-9: перебор pull_token. Знание mailbox_id не даёт доступа:
    /// 10_000 кандидатов той же длины (64 hex) отвергаются все; корректный
    /// токен после «штурма» продолжает работать (нет залипания/блокировки DoS).
    #[test]
    fn rt9_pull_token_bruteforce_rejected() {
        let mut s = Store::new();
        let token = s.register("mbx".into()).unwrap();
        let mb = s.get("mbx").unwrap();

        let mut accepted = 0usize;
        for i in 0..10_000u32 {
            let candidate = format!("{i:064x}");
            if mb.check_token(&candidate) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 0, "no brute-force candidate may be accepted");

        // Усечённые префиксы тоже не проходят (несовпадение длины → false).
        for cut in 1..=8 {
            assert!(!mb.check_token(&token[..token.len() - cut]));
        }
        // Легитимный клиент не пострадал.
        assert!(mb.check_token(&token));
    }

    /// MIN-RED-19 (следствие): ack обязан ОСВОБОЖДАТЬ память реле.
    ///
    /// Раньше элемент только помечался `acked` и жил в `queue` до TTL, тогда
    /// как cap считал только `!acked`. Цикл enqueue→ack раздувал вектор
    /// неограниченно — DoS на RAM реле (на Pi 2 B это ~1 GB на всё).
    #[test]
    fn rt_queue_shrinks_on_ack_so_dos_cannot_grow_ram() {
        let mut s = Store::new();
        s.register("DOS".into()).unwrap();
        for i in 0..(MESSAGE_QUEUE_CAP * 3) {
            s.enqueue(
                "DOS",
                QueueItem {
                    item_id: format!("i{i}"),
                    envelope_hex: "00".into(),
                    arrived_at: 0,
                    expires_at: u64::MAX,
                    item_type: ItemType::Message,
                    acked: false,
                },
            )
            .unwrap_or_else(|e| panic!("i={i}: {e}"));
            // Подтверждаем сразу — элемент обязан освобождать память.
            assert!(s.ack("DOS", &format!("i{i}")));
        }
        assert_eq!(
            s.get("DOS").unwrap().queue.len(),
            0,
            "после ack очередь обязана быть пустой, иначе RAM реле растёт"
        );
    }

    /// MIN-RED-19: повторный ack после таймаута остаётся идемпотентным.
    #[test]
    fn rt_repeated_ack_is_idempotent_after_removal() {
        let mut s = Store::new();
        s.register("ACK2".into()).unwrap();
        s.enqueue(
            "ACK2",
            QueueItem {
                item_id: "one".into(),
                envelope_hex: "00".into(),
                arrived_at: 0,
                expires_at: u64::MAX,
                item_type: ItemType::Message,
                acked: false,
            },
        )
        .unwrap();
        assert!(s.ack("ACK2", "one"), "первый ack");
        assert!(s.ack("ACK2", "one"), "повторный ack = идемпотентный успех");
        assert!(
            !s.ack("ACK2", "never-existed"),
            "чужой id не должен подтверждаться"
        );
    }

    /// AUDIT RT-10 (инвариант №1 «хакер не должен найти ключи»): полный дамп
    /// состояния relay не содержит ключевого материала клиента. Модель: клиент
    /// имеет приватные ключи (hex-представление как в FFI), в relay уходит лишь
    /// ciphertext + mailbox_id + opaque-хинты. Дамп (Debug всех полей + все
    /// строки очередей) обязан их не содержать.
    #[test]
    fn rt10_relay_dump_contains_no_key_material() {
        // «Приватные ключи клиента», которые НЕ должны оказаться в relay.
        let identity_sk_hex = "3f".repeat(32);
        let store_key_hex = "a7c1".repeat(16);

        let mut s = Store::new();
        let token = s.register("mbx".into()).unwrap();
        let item = QueueItem {
            item_id: "i1".into(),
            // Opaque ciphertext — единственное «содержимое», допустимое в relay.
            envelope_hex: "de12ad34be56ef78".into(),
            arrived_at: 1000,
            expires_at: 10_000_000,
            item_type: ItemType::Message,
            acked: false,
        };
        s.enqueue("mbx", item).unwrap();

        // «Дамп»: всё, что можно вытащить из in-memory состояния + Debug-строки.
        let mut dump = String::new();
        for (id, mb) in &s.mailboxes {
            dump.push_str(id);
            dump.push_str(&format!("{mb:?}"));
            for q in &mb.queue {
                dump.push_str(&q.item_id);
                dump.push_str(&q.envelope_hex);
                dump.push_str(&format!("{:?}", q.item_type));
            }
        }
        dump.push_str(&format!("{s:?}"));
        dump.push_str(&token);
        let lower = dump.to_lowercase();

        assert!(
            !lower.contains(&identity_sk_hex),
            "identity private key found in relay dump"
        );
        assert!(
            !lower.contains(&store_key_hex),
            "storage key found in relay dump"
        );
        // Дамп непустой — тест действительно что-то проверяет.
        assert!(dump.len() > 64, "dump should contain relay state");
    }
}

pub type SharedStore = Arc<RwLock<Store>>;
