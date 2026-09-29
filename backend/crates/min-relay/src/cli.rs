//! CLI-конфиг relay-бинаря: развёртывание на Pi 2 B v1.1 / VPS / Mac mini.
//!
//! Документация по эксплуатации хранится во внутреннем operational runbook.
//!
//! Zero-dep парсер: без clap — целевое железо ARMv7 с 1 GB RAM, лишние
//! зависимости = дольше кросс-сборка и больше поверхности. Один и тот же
//! бинарь обслуживает и прод (`--no-http`), и локальные deterministic-тесты
//! (mock REST на 127.0.0.1:3000).

use std::net::SocketAddr;
use std::path::PathBuf;

/// Прод-путь: frame API (PROTOCOL §7) — за Tor onion-сервисом.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:3001";
/// Mock REST (ТЗ §12.3) — только для тестов, в проде выключается `--no-http`.
pub const DEFAULT_HTTP: &str = "127.0.0.1:3000";
/// Дефолтный уровень логов: для беты задаётся `--log`/`RUST_LOG`.
pub const DEFAULT_LOG: &str = "info";

/// Итоговый конфиг запуска.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Адрес frame-сервера (PROTOCOL §7).
    pub listen: SocketAddr,
    /// Адрес mock REST API; `None` = не поднимать (прод).
    pub http: Option<SocketAddr>,
    /// Директива tracing-фильтра.
    pub log: String,
    /// Persistent auth-state (`mailbox_id -> hash(pull_token)`). В проде
    /// обязателен; None оставляет relay строго RAM-only для тестового стенда.
    pub state_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.parse().expect("DEFAULT_LISTEN валиден"),
            http: Some(DEFAULT_HTTP.parse().expect("DEFAULT_HTTP валиден")),
            log: DEFAULT_LOG.to_string(),
            state_dir: None,
        }
    }
}

/// Результат разбора аргументов: запуск, справка/версия или ошибка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Run(Config),
    Help,
    Version,
    Err(String),
}

/// Текст `--help` (используется и в сообщениях об ошибках).
pub fn help_text() -> String {
    format!(
        "\
MIN relay — frame API (PROTOCOL §7/§10)

Использование: min-relay [ОПЦИИ]

Опции:
  --listen ADDR   адрес frame-сервера (по умолчанию {DEFAULT_LISTEN})
  --http ADDR     адрес mock REST API (по умолчанию {DEFAULT_HTTP})
  --no-http       не поднимать mock REST API (прод-режим)
  --log FILTER    tracing-фильтр, напр. \"info\" или \"min_relay=debug,info\"
  --state-dir DIR persistent auth-state (только mailbox_id + token hash)
  -h, --help      эта справка
  -V, --version   версия

Переменные окружения:
  RUST_LOG        если задана и непустая — перекрывает --log

Замечания:
  * Queued ciphertext всегда RAM-only. В --state-dir хранится только auth-state:
    mailbox_id + BLAKE3(pull_token); token, identity и payload не пишутся.
    Резкий stop безопасен: незавершённая запись атомарно не принимается.
  * Прод: --listen 127.0.0.1:<порт> --no-http; наружу — только Tor onion.
"
    )
}

/// Разбор аргументов командной строки (без argv[0]).
pub fn parse_args<I, S>(args: I) -> ParseOutcome
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_string()).collect();
    let mut cfg = Config::default();
    let mut i = 0usize;

    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (args[i].clone(), None),
        };

        match flag.as_str() {
            "-h" | "--help" => return ParseOutcome::Help,
            "-V" | "--version" => return ParseOutcome::Version,
            "--no-http" => {
                if inline.is_some() {
                    return ParseOutcome::Err("--no-http не принимает значение".into());
                }
                cfg.http = None;
            }
            "--listen" => match value(&args, &mut i, "--listen", inline) {
                Ok(v) => match addr(&v) {
                    Ok(a) => cfg.listen = a,
                    Err(e) => return ParseOutcome::Err(e),
                },
                Err(e) => return ParseOutcome::Err(e),
            },
            "--http" => match value(&args, &mut i, "--http", inline) {
                Ok(v) => match addr(&v) {
                    Ok(a) => cfg.http = Some(a),
                    Err(e) => return ParseOutcome::Err(e),
                },
                Err(e) => return ParseOutcome::Err(e),
            },
            "--log" => match value(&args, &mut i, "--log", inline) {
                Ok(v) if v.trim().is_empty() => {
                    return ParseOutcome::Err("--log: фильтр не может быть пустым".into())
                }
                Ok(v) => cfg.log = v,
                Err(e) => return ParseOutcome::Err(e),
            },
            "--state-dir" => match value(&args, &mut i, "--state-dir", inline) {
                Ok(v) if v.trim().is_empty() => {
                    return ParseOutcome::Err("--state-dir: путь не может быть пустым".into())
                }
                Ok(v) => cfg.state_dir = Some(PathBuf::from(v)),
                Err(e) => return ParseOutcome::Err(e),
            },
            other => return ParseOutcome::Err(format!("неизвестный аргумент: {other}")),
        }
        i += 1;
    }

    ParseOutcome::Run(cfg)
}

/// Значение опции: из `--flag=value` либо из следующего аргумента.
fn value(
    args: &[String],
    i: &mut usize,
    flag: &str,
    inline: Option<String>,
) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag}: ожидается значение"))
}

fn addr(v: &str) -> Result<SocketAddr, String> {
    v.parse::<SocketAddr>()
        .map_err(|_| format!("неверный адрес '{v}' (ожидается host:port)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Config {
        match parse_args(args.iter().copied()) {
            ParseOutcome::Run(c) => c,
            other => panic!("ожидался Run, получено {other:?}"),
        }
    }

    fn err(args: &[&str]) -> String {
        match parse_args(args.iter().copied()) {
            ParseOutcome::Err(e) => e,
            other => panic!("ожидалась ошибка, получено {other:?}"),
        }
    }

    #[test]
    fn defaults_match_deploy_doc() {
        let c = run(&[]);
        assert_eq!(c.listen, DEFAULT_LISTEN.parse().unwrap());
        assert_eq!(c.http, Some(DEFAULT_HTTP.parse().unwrap()));
        assert_eq!(c.log, DEFAULT_LOG);
        assert_eq!(c.state_dir, None);
    }

    #[test]
    fn listen_accepts_both_forms() {
        assert_eq!(
            run(&["--listen", "127.0.0.1:9999"]).listen,
            "127.0.0.1:9999".parse().unwrap()
        );
        assert_eq!(
            run(&["--listen=0.0.0.0:1234"]).listen,
            "0.0.0.0:1234".parse().unwrap()
        );
    }

    #[test]
    fn no_http_disables_mock_api() {
        assert_eq!(run(&["--no-http"]).http, None);
    }

    #[test]
    fn http_addr_overrides_default() {
        assert_eq!(
            run(&["--http", "127.0.0.1:4000"]).http,
            Some("127.0.0.1:4000".parse().unwrap())
        );
    }

    #[test]
    fn log_filter_is_accepted() {
        assert_eq!(
            run(&["--log", "min_relay=debug,info"]).log,
            "min_relay=debug,info"
        );
    }

    #[test]
    fn prod_invocation_parses() {
        // Ровно строка из production systemd unit.
        let c = run(&["--listen", "127.0.0.1:3001", "--no-http"]);
        assert_eq!(c.listen, "127.0.0.1:3001".parse().unwrap());
        assert!(c.http.is_none());
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(parse_args(["-h"]), ParseOutcome::Help);
        assert_eq!(parse_args(["--help"]), ParseOutcome::Help);
        assert_eq!(parse_args(["-V"]), ParseOutcome::Version);
        assert_eq!(parse_args(["--version"]), ParseOutcome::Version);
    }

    #[test]
    fn bad_input_is_rejected() {
        assert!(err(&["--nope"]).contains("неизвестный аргумент"));
        assert!(err(&["--listen"]).contains("ожидается значение"));
        assert!(err(&["--listen", "not-an-addr"]).contains("неверный адрес"));
        assert!(err(&["--log", ""]).contains("не может быть пустым"));
        assert!(err(&["--no-http=1"]).contains("не принимает значение"));
    }

    #[test]
    fn state_dir_accepts_both_forms() {
        assert_eq!(
            run(&["--state-dir", "/var/lib/min-relay"]).state_dir,
            Some(PathBuf::from("/var/lib/min-relay"))
        );
        assert_eq!(
            run(&["--state-dir=/tmp/min-relay"]).state_dir,
            Some(PathBuf::from("/tmp/min-relay"))
        );
    }

    #[test]
    fn help_text_documents_prod_flags() {
        let h = help_text();
        assert!(h.contains("--listen") && h.contains("--no-http") && h.contains("--log"));
        assert!(h.contains("RUST_LOG"));
    }
}
