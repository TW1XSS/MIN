//! MIN relay: прод-путь — frame API (PROTOCOL §7) за Tor onion-сервисом,
//! mock REST (ТЗ §12.3) — тестовая обёртка, в проде выключается `--no-http`.
//!
//! Только opaque ciphertext, никакого plaintext / приватных ключей (ТЗ §38).
//! Очереди payload RAM-only; auth-state (mailbox_id + hash token) может быть
//! включён отдельным флагом. Резкая остановка безопасна.
//!
//! Аргументы и логирование — см. `min_relay::cli` (`--help`).

use axum::{routing, Router};
use min_relay::cli::{self, ParseOutcome};
use min_relay::handlers;
use min_relay::store::{SharedStore, Store};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let cfg = match cli::parse_args(std::env::args().skip(1)) {
        ParseOutcome::Run(cfg) => cfg,
        ParseOutcome::Help => {
            print!("{}", cli::help_text());
            return;
        }
        ParseOutcome::Version => {
            println!("min-relay {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        ParseOutcome::Err(e) => {
            eprintln!("min-relay: {e}\n\n{}", cli::help_text());
            std::process::exit(2);
        }
    };

    init_logging(&cfg.log);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %cfg.listen,
        http = ?cfg.http,
        log = %cfg.log,
        full_ids = min_relay::logfmt::full_ids(),
        state_dir = ?cfg.state_dir,
        "MIN relay starting"
    );

    let store = match cfg.state_dir.as_ref() {
        Some(path) => match Store::with_auth_state(path) {
            Ok(store) => {
                tracing::info!(state_dir = %path.display(), "persistent auth-state enabled");
                store
            }
            Err(e) => fatal(&format!("load auth-state {}: {e}", path.display())),
        },
        None => {
            tracing::warn!("no --state-dir: auth-state is RAM-only (test/dev mode)");
            Store::new()
        }
    };
    let store: SharedStore = Arc::new(RwLock::new(store));

    match cfg.http {
        // Тестовый режим: mock REST + frame API в одном процессе.
        Some(http_addr) => {
            let frame_store = Arc::clone(&store);
            let listen = cfg.listen;

            let app = Router::new()
                .route("/v1/protocol/version", routing::get(handlers::version))
                .route("/v1/mailbox/register", routing::post(handlers::register))
                .route("/v1/mailbox/queue", routing::post(handlers::enqueue))
                .route("/v1/mailbox/pull/:id", routing::get(handlers::pull))
                .route("/v1/mailbox/ack/:id", routing::post(handlers::ack_handler))
                .with_state(Arc::clone(&store));

            let listener = match tokio::net::TcpListener::bind(http_addr).await {
                Ok(l) => l,
                Err(e) => fatal(&format!("bind mock REST {http_addr}: {e}")),
            };
            tracing::warn!(
                "mock REST API listening on http://{http_addr} — test mode (spec §12.3)"
            );

            // Frame server (PROTOCOL §7) — прод-путь, за ним onion-сервис.
            tokio::spawn(async move {
                if let Err(e) =
                    min_relay::frame_server::serve_frames(frame_store, &listen.to_string()).await
                {
                    fatal(&format!("frame server: {e}"));
                }
            });

            if let Err(e) = axum::serve(listener, app).await {
                fatal(&format!("http server: {e}"));
            }
        }
        // Прод-режим: только frame API, mock REST не биндится вообще.
        None => {
            if let Err(e) =
                min_relay::frame_server::serve_frames(store, &cfg.listen.to_string()).await
            {
                fatal(&format!("frame server: {e}"));
            }
        }
    }
}

/// Логирование: `RUST_LOG` (если задан и непустой) перекрывает `--log`.
fn init_logging(cli_filter: &str) {
    let filter = match std::env::var("RUST_LOG") {
        Ok(v) if !v.trim().is_empty() => EnvFilter::new(v),
        _ => EnvFilter::new(cli_filter),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Смертельная ошибка запуска: в journal + exit 1 (systemd Restart=always).
fn fatal(msg: &str) -> ! {
    tracing::error!("{msg}");
    eprintln!("min-relay: {msg}");
    std::process::exit(1);
}
