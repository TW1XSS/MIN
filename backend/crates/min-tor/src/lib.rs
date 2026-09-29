//! Tor transport via Arti (Tor Project's Rust implementation).
//!
//! This crate is a desktop/future transport. The current iOS client uses
//! SOCKS5 to in-app C Tor + IPtProxy; both implement the same frame link
//! boundary, so switching providers does not change the wire protocol.
//!
//! Event-driven design (battery/README): no keep-alive circuits. A circuit is
//! built on demand (user opens app / push wake-up), used for the batch, then
//! torn down after an idle timeout. See `TorTransportConfig`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use rand_core::{CryptoRng, OsRng, RngCore};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_rtcompat::tokio::PreferredRuntime;
use tor_rtcompat::ToplevelBlockOn;

use min_net::{pad_payload, unpad_payload, NetError};

/// Maximum frame length on the wire (PROTOCOL §7: `len ≤ 256 КиБ`).
const MAX_FRAME: usize = 256 * 1024;

/// Errors produced by the Tor layer.
#[derive(Debug, Error)]
pub enum TorError {
    #[error("arti bootstrap failed: {0}")]
    Bootstrap(String),
    #[error("connection to relay failed: {0}")]
    Connect(String),
    #[error("network/protocol error: {0}")]
    Net(String),
    #[error("relay address is not configured (empty relay_host)")]
    NoRelay,
    #[error("payload exceeds max frame size")]
    PayloadTooLarge,
}

pub type TorResult<T> = Result<T, TorError>;

/// Transport configuration for Tor (event-driven, battery-conscious).
#[derive(Debug, Clone)]
pub struct TorTransportConfig {
    /// Onion hostname of the MIN relay, e.g. `abcd….onion` (v3, no port).
    /// The `.onion` address *is* the relay's identity: clients cryptographically
    /// pin it at setup, so no CA/PKI is needed (README: недоверенный relay).
    pub relay_host: String,
    /// TCP port of the relay's onion service.
    pub relay_port: u16,
    /// Writable directory for Tor state (required on iOS: App Support).
    pub state_dir: Option<PathBuf>,
    /// Writable directory for Tor download cache.
    pub cache_dir: Option<PathBuf>,
    /// Idle window after the last request, after which the host app should
    /// drop the handle (battery). Arti expires its circuit pool independently.
    pub idle_duration_secs: u64,
}

impl Default for TorTransportConfig {
    fn default() -> Self {
        Self {
            relay_host: String::new(),
            relay_port: 443,
            state_dir: None,
            cache_dir: None,
            idle_duration_secs: 120,
        }
    }
}

/// Event-driven Tor transport over an Arti client.
pub struct TorTransport {
    /// Arti runtime. Kept alive for the client's tasks; the process must not
    /// fork after creation (tor-rtcompat requirement).
    rt: PreferredRuntime,
    client: Arc<TorClient<PreferredRuntime>>,
    config: TorTransportConfig,
    last_activity: Instant,
}

impl TorTransport {
    /// Create and bootstrap an Arti client (blocking; call on a worker
    /// thread — never on the UI thread).
    ///
    /// First run downloads directory documents (seconds); later runs reuse
    /// the on-disk cache. On iOS callers MUST provide writable directories —
    /// Arti's default paths are not writable inside the sandbox.
    /// Create an Arti client handle *without* bootstrapping (fast, offline).
    ///
    /// Bootstrap happens lazily on the first network use (directory docs are
    /// then cached on disk). This is the right constructor for pre-network
    /// validation and for iOS wake-up paths that must not block: callers can
    /// check `bootstrapped()` and fall back to a worker-thread `connect()`
    /// when ready-for-traffic is required immediately.
    pub fn new(config: TorTransportConfig) -> TorResult<Self> {
        let rt = PreferredRuntime::create().map_err(|e| TorError::Bootstrap(e.to_string()))?;

        let cfg: TorClientConfig = match (&config.state_dir, &config.cache_dir) {
            (Some(state), Some(cache)) => TorClientConfigBuilder::from_directories(state, cache)
                .build()
                .map_err(|e| TorError::Bootstrap(e.to_string()))?,
            _ => TorClientConfigBuilder::default()
                .build()
                .map_err(|e| TorError::Bootstrap(e.to_string()))?,
        };

        let rt2 = rt.clone();
        let client = rt
            .block_on(async move {
                TorClient::with_runtime(rt2)
                    .config(cfg)
                    .create_unbootstrapped()
            })
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;

        Ok(Self {
            rt,
            client,
            config,
            last_activity: Instant::now(),
        })
    }

    pub fn connect(config: TorTransportConfig) -> TorResult<Self> {
        let rt = PreferredRuntime::create().map_err(|e| TorError::Bootstrap(e.to_string()))?;

        let cfg: TorClientConfig = match (&config.state_dir, &config.cache_dir) {
            (Some(state), Some(cache)) => TorClientConfigBuilder::from_directories(state, cache)
                .build()
                .map_err(|e| TorError::Bootstrap(e.to_string()))?,
            _ => TorClientConfigBuilder::default()
                .build()
                .map_err(|e| TorError::Bootstrap(e.to_string()))?,
        };

        let rt2 = rt.clone();
        let client = rt
            .block_on(async move {
                TorClient::with_runtime(rt2)
                    .config(cfg)
                    .create_bootstrapped()
                    .await
            })
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;

        Ok(Self {
            rt,
            client,
            config,
            last_activity: Instant::now(),
        })
    }

    fn relay_target_pair(&self) -> TorResult<(String, u16)> {
        if self.config.relay_host.is_empty() {
            return Err(TorError::NoRelay);
        }
        Ok((self.config.relay_host.clone(), self.config.relay_port))
    }

    /// One request→response round-trip over a fresh *isolated* stream.
    ///
    /// - `payload` is padded up to a size class before leaving this process
    ///   (`min_net::pad_payload`): the relay cannot infer message size from
    ///   frame length (README: минимизация метаданных).
    /// - The stream is isolated from other streams, so the relay's circuit
    ///   view cannot be correlated across batches.
    /// - Framing is exactly `u32be(len) || padded-payload` (PROTOCOL §7).
    ///
    /// Returns the relay's unpadded response.
    pub fn request<R: RngCore + CryptoRng>(
        &self,
        payload: &[u8],
        rng: &mut R,
    ) -> TorResult<Vec<u8>> {
        let padded = pad_payload(payload, rng).map_err(|e| match e {
            NetError::PayloadTooLarge => TorError::PayloadTooLarge,
            other => TorError::Net(other.to_string()),
        })?;
        let target = self.relay_target_pair()?;

        let client = self.client.isolated_client();
        let response = self.rt.block_on(async move {
            let mut stream = client
                .connect(target)
                .await
                .map_err(|e| TorError::Connect(e.to_string()))?;

            // Write: u32be(len) || padded.
            let len = u32::try_from(padded.len()).map_err(|_| TorError::PayloadTooLarge)?;
            stream
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|e| TorError::Net(e.to_string()))?;
            stream
                .write_all(&padded)
                .await
                .map_err(|e| TorError::Net(e.to_string()))?;
            stream
                .flush()
                .await
                .map_err(|e| TorError::Net(e.to_string()))?;

            // Read: u32be(len) || padded-response.
            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| TorError::Net(e.to_string()))?;
            let resp_len = u32::from_be_bytes(len_buf) as usize;
            if resp_len > MAX_FRAME {
                return Err(TorError::Net(format!(
                    "response frame {resp_len} exceeds cap {MAX_FRAME}"
                )));
            }
            let mut resp = vec![0u8; resp_len];
            stream
                .read_exact(&mut resp)
                .await
                .map_err(|e| TorError::Net(e.to_string()))?;
            Ok(resp)
        })?;

        // The response must be well-formed padding structure; anything else
        // is relay misbehaviour → hard error, no guessing (PROTOCOL §42).
        unpad_payload(&response).map_err(|e| TorError::Net(e.to_string()))
    }

    /// Marks activity (battery: idle timer is host-managed).
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// True when idle past the configured window: the host app should drop
    /// the handle and rebuild on the next wake-up.
    pub fn idle_expired(&self) -> bool {
        self.last_activity.elapsed() > Duration::from_secs(self.config.idle_duration_secs)
    }

    /// True once directory documents are loaded and circuits can be built.
    pub fn bootstrapped(&self) -> bool {
        self.client.bootstrap_status().ready_for_traffic()
    }

    /// Relay address this transport is pinned to (`host:port`), for logs/UI.
    pub fn relay_target(&self) -> String {
        if self.config.relay_host.is_empty() {
            return String::new();
        }
        format!("{}:{}", self.config.relay_host, self.config.relay_port)
    }
}

/// Прод-линк для `min_delivery::MailboxClient` (PROTOCOL §10).
///
/// `TorTransport::request` уже реализует контракт `FrameExchange`:
/// паддирует запрос до size-класса, читает паддированный ответ и
/// распаковывает его. MIN-RED-011: это скрывает размер от пассивного
/// наблюдателя канала, но не от relay — он разбирает CBOR и видит длину.
impl min_delivery::FrameExchange for TorTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, min_delivery::DeliveryError> {
        self.request(request, &mut OsRng)
            .map_err(|e| min_net::NetError::Transport(e.to_string()))
            .map_err(min_delivery::DeliveryError::Net)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Sequence for unique temp dirs (tests run in parallel threads).
    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    /// Config with unique writable temp dirs: tests must never touch Arti’s
    /// default state paths, and parallel tests must not share state locks.
    fn test_config() -> TorTransportConfig {
        let n = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let state =
            std::env::temp_dir().join(format!("min_tor_state_{}_{}", std::process::id(), n));
        let cache =
            std::env::temp_dir().join(format!("min_tor_cache_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        TorTransportConfig {
            state_dir: Some(state),
            cache_dir: Some(cache),
            ..Default::default()
        }
    }

    /// Default config is safe (no relay pinned, generous idle window).
    #[test]
    fn default_config_is_empty() {
        let cfg = TorTransportConfig::default();
        assert!(cfg.relay_host.is_empty());
        assert_eq!(cfg.relay_port, 443);
        assert!(cfg.state_dir.is_none());
        assert_eq!(cfg.idle_duration_secs, 120);
    }

    /// Oversize payloads are rejected *before* any network activity
    /// (PROTOCOL §7: `len ≤ 256 КиБ`).
    #[test]
    fn request_rejects_oversize_payload() {
        let cfg = test_config();
        let transport = TorTransport::new(cfg).expect("lazy client handle");
        let oversize = vec![0u8; MAX_FRAME + 1];
        let err = transport
            .request(&oversize, &mut OsRng)
            .expect_err("oversize must fail");
        assert!(matches!(err, TorError::PayloadTooLarge));
    }

    /// Relay must be pinned at setup: empty relay is a hard config error
    /// (README: relay пиннится у клиента, никаких « relay по умолчанию»).
    #[test]
    fn request_without_relay_is_config_error() {
        let transport = TorTransport::new(test_config()).expect("lazy client handle");
        let err = transport
            .request(b"hello", &mut OsRng)
            .expect_err("empty relay must fail");
        assert!(matches!(err, TorError::NoRelay));
    }

    /// Idle window logic (battery): fresh handle is not expired.
    #[test]
    fn idle_not_expired_when_touched() {
        let mut transport = TorTransport::new(test_config()).expect("lazy client handle");
        assert!(
            !transport.bootstrapped(),
            "new() must not bootstrap eagerly"
        );
        assert!(!transport.idle_expired());
        transport.touch();
        assert!(!transport.idle_expired());
    }

    /// `relay_target` reflects the pinned address.
    #[test]
    fn relay_target_reflects_config() {
        let cfg = TorTransportConfig {
            relay_host: "testrelay.onion".into(),
            relay_port: 9001,
            ..test_config()
        };
        let transport = TorTransport::new(cfg).expect("lazy client handle");
        assert_eq!(transport.relay_target(), "testrelay.onion:9001");
    }

    /// REAL Tor bootstrap (needs network; run manually):
    /// `cargo test -p min-tor --release -- --ignored tor_bootstraps_real_network`
    ///
    /// Validates that arti-client can bootstrap a real client on this host
    /// using temp state/cache dirs (iOS provides its own writable dirs).
    #[test]
    #[ignore = "requires network access"]
    fn tor_bootstraps_real_network() {
        let state = std::env::temp_dir().join("min_tor_test_state");
        let cache = std::env::temp_dir().join("min_tor_test_cache");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&cache).unwrap();

        let cfg = TorTransportConfig {
            state_dir: Some(state),
            cache_dir: Some(cache),
            ..Default::default()
        };
        let transport = TorTransport::connect(cfg).expect("real bootstrap succeeds");
        assert!(
            transport.bootstrapped(),
            "directory documents must be loaded"
        );
    }
}
