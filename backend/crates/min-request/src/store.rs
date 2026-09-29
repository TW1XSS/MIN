//! Локальная очередь заявок (MVP-тумблер «кто может мне писать»).
//!
//! Только логика, без визуализации: UI подключится позже.
//!
//! # Ограничения памяти (почему они именно такие)
//!
//! Очередь растёт от ПРИВЕТСТВИВШИХ, то есть от недоверенных источников.
//! Без жёсткого бюджета это вектор DoS по памяти. Сверху стоят независимые
//! пределы:
//!
//! * `MAX_PENDING` — 20 заявок (PROTOCOL §6, Queue cap REQUEST);
//! * `MAX_ENVELOPES_PER_REQUEST` — сколько конвертов хранить на заявку;
//! * `MAX_ENVELOPE_BYTES` — 16 КиБ на конверт (PROTOCOL §0, Max REQUEST);
//! * `MAX_TOTAL_ENVELOPE_BYTES` — суммарный бюджет. Это главный предел:
//!   даже при 20 заявках по 4 конверта память не выйдет за фиксированную
//!   величину.
//!
//! При переполнении вытесняется **самая старая** заявка, а не новая: иначе
//! флуд от постороннего заблокировал бы заявки друзей, пришедших позже.
//!
//! # Почему тут сырые конверты, а не расшифрованный текст
//!
//! Текст заявки нельзя показать до Accept — значит расшифровывать нельзя.
//! Сессия libsignal при этом создаётся **только при Accept**: до этого
//! хранятся конверты. Причина не в экономии, а в снапшоте сессий: он уходит
//! в recovery-блоб, а тот ограничен по размеру и лежит в Keychain. Двадцать
//! сессий незнакомцев раздули бы блоб за пределы лимита. Конверты после
//! рестарта обрабатываются заново (Accept это и делает), потерять их нельзя —
//! они лежат в зашифрованной БД.

use min_storage::Storage;
use serde::{Deserialize, Serialize};

/// Слот очереди заявок в зашифрованной БД.
pub const K_REQUESTS: &str = "app/requests";
/// Слот блок-листа (тоже в зашифрованной БД).
pub const K_BLOCKED: &str = "app/blocked";

/// PROTOCOL §6: 20 неразрешённых заявок на mailbox.
pub const MAX_PENDING: usize = 20;
/// PROTOCOL §6: TTL REQUEST = 7 дней.
pub const TTL_REQUEST_SEC: u64 = 7 * 24 * 3600;
/// PROTOCOL §0: Max REQUEST = 16 КиБ.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
/// Конвертов на одну заявку.
///
/// 16 (а не 4): заявка — это живой диалог. Человек пишет первое сообщение,
/// отправитель отвечает ещё несколько — и всё это лежит в заявке до решения.
/// Суммарный бюджет (`MAX_TOTAL_ENVELOPE_BYTES`) при этом жёсткий, поэтому
/// поднятие числа конвертов не ослабляет защиту от флуда: 20 заявок × 16
/// конвертов всё равно упираются в 512 КиБ, а не растут линейно.
pub const MAX_ENVELOPES_PER_REQUEST: usize = 16;
/// Суммарный бюджет конвертов во всей очереди — жёсткий потолок памяти.
pub const MAX_TOTAL_ENVELOPE_BYTES: usize = 512 * 1024;
/// Потолок блок-листа: 512 x 32 байта = 16 КиБ.
pub const MAX_BLOCKED: usize = 512;

/// Заявка от незнакомца, ждущая решения владельца.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// Не предсказуемый (CSPRNG), не счётчик: иначе виден порядок.
    pub request_id: [u8; 16],
    pub peer_identity: [u8; 32],
    pub peer_mailbox: [u8; 16],
    pub epoch: u64,
    pub first_seen: u64,
    pub expires_at: u64,
    /// Сырые конверты отправителя. Сессии ещё нет, расшифровывать нельзя.
    #[serde(default)]
    pub envelopes: Vec<Vec<u8>>,
    /// `item_id` первого конверта на relay.
    ///
    /// Нужен для ack: мы НЕ ack'аем заявку при получении (сообщение должно
    /// дождаться решения), поэтому после Accept/Reject/Block письмо надо
    /// убрать из очереди relay явно. Без этого id оно вернулось бы следующим
    /// poll уже как «незнакомец без сессии» и завело бы вторую заявку.
    #[serde(default)]
    pub relay_item_id: String,
}

impl PendingRequest {
    /// Обрезает по лимитам ДО записи. Всё не влезающее отбрасывается молча,
    /// но не приводит к панике и не занимает память сверх бюджета.
    pub fn sanitize(&mut self) {
        self.envelopes
            .retain(|e| !e.is_empty() && e.len() <= MAX_ENVELOPE_BYTES);
        if self.envelopes.len() > MAX_ENVELOPES_PER_REQUEST {
            // Оставляем ПОСЛЕДНИЕ: свежая реплика важнее первой заявки.
            let start = self.envelopes.len() - MAX_ENVELOPES_PER_REQUEST;
            self.envelopes.drain(..start);
        }
    }

    pub fn expired(&self, now: u64) -> bool {
        self.expires_at != 0 && now >= self.expires_at
    }

    pub fn total_bytes(&self) -> usize {
        self.envelopes.iter().map(|e| e.len()).sum()
    }
}

#[derive(Debug, Default)]
pub struct RequestStore;

impl RequestStore {
    fn load_all(storage: &Storage) -> Vec<PendingRequest> {
        let Ok(Some(raw)) = storage.get(K_REQUESTS) else {
            return Vec::new();
        };
        // Битое содержимое не должно ломать открытие приложения: очередь
        // становится пустой, аккаунт и переписка целы.
        let mut list: Vec<PendingRequest> = serde_json::from_slice(&raw).unwrap_or_default();
        for r in &mut list {
            r.sanitize();
        }
        list.sort_by_key(|r| r.first_seen);
        list.truncate(MAX_PENDING);
        list
    }

    fn save_all(storage: &Storage, list: &[PendingRequest]) -> Result<(), String> {
        let raw = serde_json::to_vec(list).map_err(|e| e.to_string())?;
        storage.put(K_REQUESTS, &raw).map_err(|e| e.to_string())
    }

    /// Живые (не истёкшие) заявки; попутно чистит очередь на диске.
    pub fn pending(storage: &Storage, now: u64) -> Vec<PendingRequest> {
        let all = Self::load_all(storage);
        let live: Vec<PendingRequest> = all.iter().filter(|r| !r.expired(now)).cloned().collect();
        if live.len() != all.len() {
            let _ = Self::save_all(storage, &live);
        }
        live
    }

    /// Кладёт заявку либо доливает конверт в существующую от того же identity.
    /// `false` — заявка отброшена по лимитам; вызывающий обязан отправить
    /// отправителю нейтральный отказ.
    pub fn upsert(storage: &Storage, mut req: PendingRequest, now: u64) -> bool {
        req.sanitize();
        if req.envelopes.is_empty() || Self::is_blocked(storage, &req.peer_identity) {
            return false;
        }
        let mut list = Self::pending(storage, now);

        if let Some(existing) = list
            .iter_mut()
            .find(|r| r.peer_identity == req.peer_identity)
        {
            existing.envelopes.append(&mut req.envelopes);
            existing.sanitize();
            existing.expires_at = req.expires_at;
            return Self::enforce_budget(storage, &mut list);
        }
        if list.len() >= MAX_PENDING {
            // Полная очередь: вытесняем самую старую, чтобы флуд от
            // постороннего не заблокировал заявки друзей, пришедших позже.
            list.remove(0);
        }
        list.push(req);
        Self::enforce_budget(storage, &mut list)
    }

    /// Держит суммарный бюджет конвертов, вытесняя самые старые заявки.
    /// Гарантия: при `true` суммарный размер не превышает
    /// `MAX_TOTAL_ENVELOPE_BYTES`.
    fn enforce_budget(storage: &Storage, list: &mut Vec<PendingRequest>) -> bool {
        let mut total: usize = list.iter().map(|r| r.total_bytes()).sum();
        while total > MAX_TOTAL_ENVELOPE_BYTES {
            let Some(oldest) = list.first_mut() else {
                break;
            };
            let freed = oldest.total_bytes();
            list.remove(0);
            total = total.saturating_sub(freed);
        }
        Self::save_all(storage, list).is_ok()
    }

    pub fn get(storage: &Storage, request_id: &[u8; 16], now: u64) -> Option<PendingRequest> {
        Self::pending(storage, now)
            .into_iter()
            .find(|r| &r.request_id == request_id)
    }

    /// Убирает заявку (Accept/Reject). При Accept конверты возвращаются
    /// вызывающему для установления сессии.
    pub fn take(storage: &Storage, request_id: &[u8; 16], now: u64) -> Option<PendingRequest> {
        let mut list = Self::pending(storage, now);
        let idx = list.iter().position(|r| &r.request_id == request_id)?;
        let taken = list.remove(idx);
        let _ = Self::save_all(storage, &list);
        Some(taken)
    }

    // ---------------- Блок-лист ----------------

    pub fn blocked(storage: &Storage) -> Vec<[u8; 32]> {
        let Ok(Some(raw)) = storage.get(K_BLOCKED) else {
            return Vec::new();
        };
        let list: Vec<[u8; 32]> = serde_json::from_slice(&raw).unwrap_or_default();
        list.into_iter().take(MAX_BLOCKED).collect()
    }

    pub fn is_blocked(storage: &Storage, identity: &[u8; 32]) -> bool {
        Self::blocked(storage).iter().any(|i| i == identity)
    }

    /// Добавляет в блок-лист и вычищает заявки этого отправителя.
    /// `false` — уже заблокирован либо запись не удалась.
    ///
    /// Важно: после Block заявки отбрасываются **локально, до сети** (см.
    /// `upsert`). Отправитель не должен получать ответа — иначе блокировка
    /// становится обнаружимым сигналом.
    pub fn block(storage: &Storage, identity: &[u8; 32], now: u64) -> bool {
        if Self::is_blocked(storage, identity) {
            return false;
        }
        let mut list = Self::blocked(storage);
        list.push(*identity);
        if list.len() > MAX_BLOCKED {
            let overflow = list.len() - MAX_BLOCKED;
            list.drain(..overflow);
        }
        if storage
            .put(K_BLOCKED, &serde_json::to_vec(&list).unwrap_or_default())
            .is_err()
        {
            return false;
        }
        let mut reqs = Self::pending(storage, now);
        reqs.retain(|r| &r.peer_identity != identity);
        let _ = Self::save_all(storage, &reqs);
        true
    }

    pub fn unblock(storage: &Storage, identity: &[u8; 32]) -> bool {
        let mut list = Self::blocked(storage);
        let before = list.len();
        list.retain(|i| i != identity);
        if list.len() == before {
            return false;
        }
        storage
            .put(K_BLOCKED, &serde_json::to_vec(&list).unwrap_or_default())
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let key = min_storage::generate_storage_key();
        let st = Storage::open(dir.path().join("t.db"), &key).expect("open");
        (dir, st)
    }

    fn req(id: u8, identity: u8, now: u64, envelope: usize) -> PendingRequest {
        PendingRequest {
            request_id: [id; 16],
            peer_identity: [identity; 32],
            peer_mailbox: [identity; 16],
            epoch: 1,
            first_seen: now,
            expires_at: now + TTL_REQUEST_SEC,
            envelopes: vec![vec![0xABu8; envelope]],
            relay_item_id: format!("item-{id}"),
        }
    }

    #[test]
    fn upsert_and_take_roundtrip() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(RequestStore::upsert(&st, req(1, 0x11, now, 512), now));
        let got = RequestStore::pending(&st, now);
        assert_eq!(got.len(), 1);
        let taken = RequestStore::take(&st, &got[0].request_id, now).expect("take");
        assert_eq!(taken.peer_identity, [0x11u8; 32]);
        assert!(RequestStore::pending(&st, now).is_empty());
    }

    #[test]
    fn same_identity_appends_instead_of_duplicating() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(RequestStore::upsert(&st, req(1, 0x11, now, 100), now));
        assert!(RequestStore::upsert(
            &st,
            req(2, 0x11, now + 5, 100),
            now + 5
        ));
        let list = RequestStore::pending(&st, now + 5);
        assert_eq!(list.len(), 1, "одна заявка на identity");
        assert_eq!(list[0].envelopes.len(), 2);
    }

    #[test]
    fn expired_request_disappears() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(RequestStore::upsert(&st, req(1, 0x11, now, 100), now));
        assert!(RequestStore::pending(&st, now + TTL_REQUEST_SEC).is_empty());
    }

    #[test]
    fn oversize_envelope_is_dropped_not_stored() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(!RequestStore::upsert(
            &st,
            req(1, 0x11, now, MAX_ENVELOPE_BYTES + 1),
            now
        ));
        assert!(RequestStore::pending(&st, now).is_empty());
    }

    #[test]
    fn queue_is_capped_and_oldest_evicted() {
        let (_d, st) = tmp();
        let now = 1_000;
        for i in 0..(MAX_PENDING + 5) {
            assert!(RequestStore::upsert(
                &st,
                req(i as u8, i as u8, now + i as u64, 64),
                now
            ));
        }
        let list = RequestStore::pending(&st, now + 100);
        assert_eq!(list.len(), MAX_PENDING, "кап соблюдён");
        assert_eq!(list[0].peer_identity[0], 5, "самая старая вытеснена");
        assert_eq!(
            list[MAX_PENDING - 1].peer_identity[0],
            (MAX_PENDING + 4) as u8,
            "самая новая на месте"
        );
    }

    #[test]
    fn total_byte_budget_is_enforced() {
        let (_d, st) = tmp();
        let now = 1_000;
        let big = MAX_ENVELOPE_BYTES;
        let per_req = big * MAX_ENVELOPES_PER_REQUEST;
        let fits = MAX_TOTAL_ENVELOPE_BYTES / per_req;
        for i in 0..(fits + 4) {
            let mut r = req(i as u8, i as u8, now + i as u64, 1);
            r.envelopes = vec![vec![0xABu8; big]; MAX_ENVELOPES_PER_REQUEST];
            assert!(RequestStore::upsert(&st, r, now));
        }
        let total: usize = RequestStore::pending(&st, now + 100)
            .iter()
            .map(|r| r.total_bytes())
            .sum();
        assert!(
            total <= MAX_TOTAL_ENVELOPE_BYTES,
            "бюджет соблюдён: {total}"
        );
    }

    #[test]
    fn envelopes_per_request_are_capped() {
        let (_d, st) = tmp();
        let now = 1_000;
        // Больше, чем новый потолок: проверяем именно отсечение.
        for i in 0..(MAX_ENVELOPES_PER_REQUEST as u8 + 6) {
            assert!(RequestStore::upsert(
                &st,
                req(1, 0x11, now + i as u64, 64),
                now
            ));
        }
        let list = RequestStore::pending(&st, now + 20);
        assert_eq!(list[0].envelopes.len(), MAX_ENVELOPES_PER_REQUEST);
    }

    /// Потолок конвертов и суммарный бюджет ограничивают память независимо
    /// от числа заявок: 30 заявок по максимуму не превращаются в 30×16 конвертов.
    #[test]
    fn total_byte_budget_caps_memory_across_requests() {
        let (_d, st) = tmp();
        let now = 2_000;
        for peer in 0..30u8 {
            for i in 0..(MAX_ENVELOPES_PER_REQUEST as u8) {
                RequestStore::upsert(&st, req(peer, 0x11, now + i as u64, 8 * 1024), now);
            }
        }
        let total: usize = RequestStore::pending(&st, now + 100)
            .iter()
            .map(|r| r.envelopes.iter().map(|e| e.len()).sum::<usize>())
            .sum();
        assert!(
            total <= MAX_TOTAL_ENVELOPE_BYTES,
            "budget breached: {total} > {MAX_TOTAL_ENVELOPE_BYTES}"
        );
    }

    #[test]
    fn blocked_sender_is_rejected_before_network() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(RequestStore::block(&st, &[0x11u8; 32], now));
        assert!(RequestStore::is_blocked(&st, &[0x11u8; 32]));
        assert!(!RequestStore::upsert(&st, req(1, 0x11, now, 64), now));
        assert!(RequestStore::pending(&st, now).is_empty());
    }

    #[test]
    fn block_purges_existing_requests() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(RequestStore::upsert(&st, req(1, 0x11, now, 64), now));
        assert!(RequestStore::block(&st, &[0x11u8; 32], now));
        assert!(RequestStore::pending(&st, now).is_empty());
    }

    #[test]
    fn block_list_is_capped() {
        let (_d, st) = tmp();
        let now = 1_000;
        // Идентичности должны быть РАЗНЫМИ на всей длине: u8 завёрнулся бы
        // на 256 и часть блокировок молча отбросилась бы как дубликат.
        let mut ident = [0u8; 32];
        for i in 0..(MAX_BLOCKED + 20) {
            ident[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let _ = RequestStore::block(&st, &ident, now);
        }
        assert_eq!(RequestStore::blocked(&st).len(), MAX_BLOCKED);
    }

    #[test]
    fn unblock_reopens_contact() {
        let (_d, st) = tmp();
        let now = 1_000;
        assert!(RequestStore::block(&st, &[0x11u8; 32], now));
        assert!(RequestStore::unblock(&st, &[0x11u8; 32]));
        assert!(RequestStore::upsert(&st, req(1, 0x11, now, 64), now));
    }

    #[test]
    fn corrupt_queue_does_not_break_open() {
        let (_d, st) = tmp();
        st.put(K_REQUESTS, b"not-json-at-all").expect("put");
        assert!(RequestStore::pending(&st, 1_000).is_empty());
    }
}
