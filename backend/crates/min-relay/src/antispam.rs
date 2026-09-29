//! Anti-spam rate limiting (ТЗ §8.7): token bucket per mailbox.
//!
//! Relay — недоверенный компонент, но обязан защищать себя от шторма:
//! агрегация запросов, rate-limit, без бесконечного ретрая. Не влияет на
//! wire-формат (PROTOCOL.md §10), работает поверх store.
//!
//! Подключение (AUDIT MIN-01): лимитер живёт внутри `Store` и проверяется
//! в `frame_server::handle_frame` (прод-путь) и REST-хендлерах (тестовая
//! обёртка) перед выполнением операции. Burst 30 / 2 токена в секунду
//! на mailbox: легитимный чат-трафик проходит, флуд 10k/sec капится
//! до 2 ops/s sustained. Конфиг — MVP; тюнинг прод-значений отдельно.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Конфигурация лимитов.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Ёмкость bucket (максимум операций сразу).
    pub burst: u32,
    /// Скорость пополнения (токенов в секунду).
    pub refill_per_sec: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 30,
            refill_per_sec: 2.0,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(config: &RateLimitConfig) -> Self {
        Self {
            tokens: config.burst as f64,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, config: &RateLimitConfig) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * config.refill_per_sec).min(config.burst as f64);
            self.last_refill = Instant::now();
        }
    }

    fn try_take(&mut self, config: &RateLimitConfig, cost: u32) -> bool {
        self.refill(config);
        let cost = cost as f64;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Rate limiter: token bucket на ключ (mailbox_id отправителя/получателя).
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: HashMap<String, Bucket>,
    last_sweep: Instant,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Проверяет и списывает `cost` токенов для ключа.
    /// true = операция разрешена, false = rate limited.
    pub fn check(&mut self, key: &str, cost: u32) -> bool {
        self.check_bounded(key, cost, usize::MAX)
    }

    /// Ограниченная variant для attacker-controlled keys: при заполненной карте
    /// новый key не создаётся (false), global bucket всё равно ограничивает трафик.
    pub fn check_bounded(&mut self, key: &str, cost: u32, max_buckets: usize) -> bool {
        if !self.buckets.contains_key(key) && self.buckets.len() >= max_buckets {
            // Полный scan максимум раз в час: flood новых keys не превращает
            // bounded-защиту в O(cap) CPU DoS.
            if self.last_sweep.elapsed() >= Duration::from_secs(3600) {
                self.sweep_idle(Duration::from_secs(3600));
                self.last_sweep = Instant::now();
            }
            if !self.buckets.contains_key(key) && self.buckets.len() >= max_buckets {
                return false;
            }
        }
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(&self.config));
        bucket.try_take(&self.config, cost)
    }

    /// Проверяет без списания (peek).
    pub fn peek(&mut self, key: &str) -> bool {
        self.buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::new(&self.config))
            .refill(&self.config);
        let bucket = self.buckets.get(key).unwrap();
        bucket.tokens >= 1.0
    }

    /// Чистит «остывшие» bucket'ы (не использовались дольше idle).
    /// Вызывается периодически, чтобы не копить память.
    pub fn sweep_idle(&mut self, idle: Duration) -> usize {
        let before = self.buckets.len();
        self.buckets.retain(|_, b| b.last_refill.elapsed() < idle);
        self.last_sweep = Instant::now();
        before - self.buckets.len()
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Стоимость операций (REQUEST дороже — анти-спам приоритет).
pub mod op_cost {
    pub const REGISTER: u32 = 2;
    pub const ENQUEUE_REQUEST: u32 = 3;
    pub const ENQUEUE_MESSAGE: u32 = 1;
    pub const PULL: u32 = 1;
    pub const ACK: u32 = 1;
    pub const INVITE_PUBLISH: u32 = 2;
    pub const INVITE_CLAIM: u32 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_limits() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            burst: 3,
            refill_per_sec: 0.0, // без пополнения для детерминизма
        });
        assert!(rl.check("alice", 1));
        assert!(rl.check("alice", 1));
        assert!(rl.check("alice", 1));
        assert!(!rl.check("alice", 1), "4th op must be rate limited");
        // другой ключ — свой bucket
        assert!(rl.check("bob", 1));
    }

    #[test]
    fn refill_over_time() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            burst: 1,
            refill_per_sec: 100.0, // быстрое пополнение
        });
        assert!(rl.check("alice", 1));
        // 25ms × 100 токенов/сек = 2.5 токена, но burst=1 каппит до 1 →
        // достаточно ровно на 1 операцию
        std::thread::sleep(Duration::from_millis(25));
        assert!(rl.check("alice", 1), "refill must restore tokens");
        // tokens=0 снова; без ожидания пополнения нет
        assert!(!rl.check("alice", 1), "no refill within same instant");
    }

    #[test]
    fn cost_scaling() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            burst: 5,
            refill_per_sec: 0.0,
        });
        // REGISTER стоит 2: 2 ops, потом не хватает на 3-й
        assert!(rl.check("alice", op_cost::REGISTER));
        assert!(rl.check("alice", op_cost::REGISTER));
        assert!(!rl.check("alice", op_cost::REGISTER));
    }

    #[test]
    fn peek_does_not_consume() {
        let mut rl = RateLimiter::new(RateLimitConfig::default());
        assert!(rl.peek("carol"));
        assert!(rl.peek("carol"));
        assert!(rl.peek("carol"));
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn sweep_removes_idle() {
        let mut rl = RateLimiter::new(RateLimitConfig::default());
        let _ = rl.check("alice", 1);
        let _ = rl.check("bob", 1);
        assert_eq!(rl.len(), 2);
        // нулевой idle удаляет всё
        let removed = rl.sweep_idle(Duration::ZERO);
        assert_eq!(removed, 2);
        assert!(rl.is_empty());
    }

    #[test]
    fn bounded_bucket_map_rejects_new_keys_without_growing() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            burst: 2,
            refill_per_sec: 0.0,
        });
        assert!(rl.check_bounded("a", 1, 2));
        assert!(rl.check_bounded("b", 1, 2));
        assert!(!rl.check_bounded("c", 1, 2));
        assert_eq!(rl.len(), 2, "new key must not allocate after cap");
    }

    #[test]
    fn default_config_sane() {
        let c = RateLimitConfig::default();
        assert!(c.burst >= 5, "burst должен пропускать нормальный трафик");
        assert!(c.refill_per_sec > 0.0, "должно быть пополнение");
    }
}
