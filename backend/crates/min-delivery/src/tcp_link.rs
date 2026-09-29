//! Блокирующий TCP-линк (`FrameExchange`) — localhost-тесты и dev-инструменты.
//!
//! Политика (PROTOCOL §7 / README): прямой TCP — НЕ прод-транспорт, прод —
//! Tor (`min_tor::TorTransport` реализует тот же `FrameExchange`).
//!
//! Паддинг: запрос паддируется до size-класса (min-net) перед отправкой,
//! ответ распаковывается после чтения. MIN-RED-011: размер конверта остаётся
//! виден relay, так как CBOR `bstr` объявляет длину явно.

use std::net::TcpStream;

use min_net::{read_frame, unpad_payload, write_frame};
use rand_core::OsRng;

use crate::{DeliveryError, FrameExchange};

/// Кадр превышает лимит §7 — ошибка линка.
const MAX_FRAME: usize = 256 * 1024;

pub struct TcpLink {
    addr: String,
    stream: Option<TcpStream>,
}

impl TcpLink {
    /// Ссылка на relay: `host:port`. Соединение ленивое — устанавливается
    /// на первом `exchange`.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
        }
    }

    fn connect(&mut self) -> Result<&mut TcpStream, DeliveryError> {
        if self
            .stream
            .as_ref()
            .map(|s| s.peer_addr().is_err())
            .unwrap_or(true)
        {
            // Не удалось открыть TCP (relay ничего не получил) → повтор безопасен.
            let s = TcpStream::connect(&self.addr)
                .map_err(|e| DeliveryError::Connect(min_net::NetError::Transport(e.to_string())))?;
            // Короткие операции: держим сокет живым до дропа линка.
            s.set_nodelay(true).ok();
            self.stream = Some(s);
        }
        Ok(self.stream.as_mut().expect("just connected"))
    }
}

impl FrameExchange for TcpLink {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, DeliveryError> {
        let stream = self.connect()?;

        // Запрос: паддированный кадр §7.
        let padded = min_net::pad_payload(request, &mut OsRng).map_err(DeliveryError::Net)?;
        write_frame(stream, &padded).map_err(DeliveryError::Net)?;

        // Ответ: паддированный кадр §7 → распаковка.
        let resp = read_frame(stream)
            .map_err(DeliveryError::Net)?
            .ok_or_else(|| {
                DeliveryError::Net(min_net::NetError::Transport("relay closed".into()))
            })?;
        if resp.len() > MAX_FRAME {
            return Err(DeliveryError::Net(min_net::NetError::PayloadTooLarge));
        }
        unpad_payload(&resp).map_err(DeliveryError::Net)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeliveryError, MailboxClient, TOKEN_LEN};
    use min_protocol::frame_api::{FrameError, QueueItemType};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Полный цикл клиент—relay через реальный TCP-линк и паддинг:
    /// register → enqueue → pull → ack → пустой pull.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_cycle_over_real_relay() {
        // Поднимаем relay frame server на эфемерном порту.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = probe.local_addr().unwrap();
        drop(probe);
        let store: min_relay::store::SharedStore =
            Arc::new(RwLock::new(min_relay::store::Store::new()));
        tokio::spawn(async move {
            min_relay::frame_server::serve_frames(store, &bound.to_string())
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let link = TcpLink::new(bound.to_string());
        let mut client = MailboxClient::new(link);

        // 1. Register (claim-once).
        let (epoch, token) = client.register("ALICE").expect("register");
        assert_eq!(epoch, 1);

        // 2. Enqueue от «Боба» в ящик Алисы.
        let (item_id, _exp) = client
            .enqueue("ALICE", &vec![7u8; 512], QueueItemType::Message)
            .expect("enqueue");

        // 3. Pull Алисы — видит сообщение Боба.
        let items = client.pull("ALICE", &token).expect("pull");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_id, item_id);
        assert_eq!(items[0].envelope, vec![7u8; 512]);

        // 4. Неверный токен → Relay(FrameError::Forbidden).
        let err = client
            .pull("ALICE", &[0u8; TOKEN_LEN])
            .expect_err("must be forbidden");
        assert!(matches!(err, DeliveryError::Relay(FrameError::Forbidden)));

        // 5. Ack удаляет, повторный pull пуст.
        let acked = client
            .ack("ALICE", &token, &[items[0].item_id.clone()])
            .expect("ack");
        assert_eq!(acked, 1);
        let items = client.pull("ALICE", &token).expect("pull2");
        assert!(items.is_empty());

        // 6. Повторный register того же mailbox → Conflict.
        let err = client.register("ALICE").expect_err("conflict");
        assert!(matches!(err, DeliveryError::Relay(FrameError::Conflict)));
    }
}
