//! Зашифрованное локальное хранилище (SQLite + row-level XChaCha20-Poly1305).
//!
//! Каждая запись шифруется отдельно с уникальным nonce (random 24 байта).
//! Ключ шифрования хранится только в памяти и должен быть обёрнут в Keychain
//! вызывающей стороной (iOS: kSecAttrAccessibleWhenUnlockedThisDeviceOnly).

use chacha20poly1305::{
    aead::{Aead as AeadOps, NewAead, Payload},
    Key, XChaCha20Poly1305 as Aead, XNonce,
};
use rand_core::OsRng;
use rand_core::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

pub struct Storage {
    conn: Connection,
    cipher: Aead,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

pub fn generate_storage_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut key);
    key
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Storage {
    pub fn open<P: AsRef<Path>>(path: P, key: &[u8; KEY_LEN]) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        let key = Key::from_slice(key);
        let cipher = Aead::new(&key);

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS kv (
                 key TEXT PRIMARY KEY,
                 nonce BLOB NOT NULL,
                 ciphertext BLOB NOT NULL,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );",
        )?;

        Ok(Self { conn, cipher })
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM kv WHERE key = ?1",
                params![key],
                |row| {
                    let nonce: Vec<u8> = row.get(0)?;
                    let ciphertext: Vec<u8> = row.get(1)?;
                    Ok((nonce, ciphertext))
                },
            )
            .optional()?;

        match row {
            Some((nonce, ciphertext)) => {
                let plaintext = self.decrypt(&nonce, &ciphertext, key)?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let ciphertext = self.encrypt(&nonce_bytes, value, key)?;
        let now = now_secs();

        self.conn.execute(
            "INSERT INTO kv (key, nonce, ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(key) DO UPDATE SET
                 nonce = excluded.nonce,
                 ciphertext = excluded.ciphertext,
                 updated_at = excluded.updated_at",
            params![key, &nonce_bytes[..], &ciphertext, now],
        )?;

        Ok(())
    }

    pub fn delete(&self, key: &str) -> Result<bool, StorageError> {
        let affected = self
            .conn
            .execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        Ok(affected > 0)
    }

    pub fn list_keys(&self) -> Result<Vec<String>, StorageError> {
        let mut stmt = self.conn.prepare("SELECT key FROM kv ORDER BY key")?;
        let keys = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keys)
    }

    pub fn len(&self) -> Result<usize, StorageError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM kv", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    pub fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }

    /// AUDIT MIN-04: AAD привязывает шифротекст к слоту (имени ключа) —
    /// подмена ciphertext'а одной записи в слот другой (row-swapping)
    /// блокируется AEAD-тегом. Формат: `min-storage/v1/kv/<key>`.
    fn row_aad(key: &str) -> Vec<u8> {
        format!("min-storage/v1/kv/{key}").into_bytes()
    }

    fn encrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        key: &str,
    ) -> Result<Vec<u8>, StorageError> {
        let nonce = XNonce::from_slice(nonce);
        AeadOps::encrypt(
            &self.cipher,
            nonce,
            Payload {
                msg: plaintext,
                aad: &Self::row_aad(key),
            },
        )
        .map_err(|e| StorageError::Crypto(e.to_string()))
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], key: &str) -> Result<Vec<u8>, StorageError> {
        if nonce.len() != NONCE_LEN {
            return Err(StorageError::Crypto("invalid storage nonce length".into()));
        }
        let nonce = XNonce::from_slice(nonce);
        AeadOps::decrypt(
            &self.cipher,
            nonce,
            Payload {
                msg: ciphertext,
                aad: &Self::row_aad(key),
            },
        )
        .map_err(|e| StorageError::Crypto(format!("decryption failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn test_storage() -> (Storage, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let key = generate_storage_key();
        let storage = Storage::open(file.path(), &key).unwrap();
        (storage, file)
    }

    #[test]
    fn test_open_creates_db() {
        let (_storage, _file) = test_storage();
    }

    #[test]
    fn test_put_and_get() {
        let (storage, _file) = test_storage();
        storage.put("hello", b"world").unwrap();
        let value = storage.get("hello").unwrap();
        assert_eq!(value, Some(b"world".to_vec()));
    }

    /// AUDIT MIN-04: подмена шифротекста одной записи в слот другой
    /// (row-swapping) обязана провалиться — AAD привязан к имени ключа.
    #[test]
    fn test_row_swap_attack_rejected() {
        let (storage, _file) = test_storage();
        storage.put("secret:a", b"payload-a").unwrap();
        storage.put("secret:b", b"payload-b").unwrap();

        // «Атакующий» с доступом к файлу БД меняет ciphertext'ы местами
        // (nonce'ы остаются на местах).
        {
            let ca: Option<Vec<u8>> = storage
                .conn
                .query_row(
                    "SELECT ciphertext FROM kv WHERE key = 'secret:a'",
                    [],
                    |r| r.get(0),
                )
                .ok();
            let cb: Option<Vec<u8>> = storage
                .conn
                .query_row(
                    "SELECT ciphertext FROM kv WHERE key = 'secret:b'",
                    [],
                    |r| r.get(0),
                )
                .ok();
            let (ca, cb) = (ca.unwrap(), cb.unwrap());
            storage
                .conn
                .execute(
                    "UPDATE kv SET ciphertext = ?1 WHERE key = 'secret:a'",
                    [&cb[..]],
                )
                .unwrap();
            storage
                .conn
                .execute(
                    "UPDATE kv SET ciphertext = ?1 WHERE key = 'secret:b'",
                    [&ca[..]],
                )
                .unwrap();
        }

        // Чтение подменённых записей → ошибка расшифровки, не чужой plaintext.
        assert!(
            storage.get("secret:a").is_err(),
            "swapped row must fail to decrypt"
        );
        assert!(
            storage.get("secret:b").is_err(),
            "swapped row must fail to decrypt"
        );
    }

    /// AUDIT RT-26.19b (PoC, Phase 4 v6): полная матрица row-level атак
    /// «атакующий с доступом к файлу БД»:
    /// (1) swap ciphertext (covered в базовом тесте), (2) swap nonce,
    /// (3) cross-DB swap обеих колонок, (4) copy-attack (nonce+ct одной
    /// строки → другой слот). Всё ловится AEAD-тегом (AAD/nonce-binding).
    #[test]
    fn rt26_19b_storage_row_swap_poc_matrix() {
        let (storage, _file) = test_storage();
        storage.put("slot:a", b"payload-a").unwrap();
        storage.put("slot:b", b"payload-b").unwrap();

        let read_row = |storage: &Storage, key: &str| -> (Vec<u8>, Vec<u8>) {
            storage
                .conn
                .query_row(
                    "SELECT nonce, ciphertext FROM kv WHERE key = ?1",
                    [key],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )
                .unwrap()
        };
        let write_row = |storage: &Storage, key: &str, nonce: &[u8], ct: &[u8]| {
            storage
                .conn
                .execute(
                    "UPDATE kv SET nonce = ?1, ciphertext = ?2 WHERE key = ?3",
                    params![nonce, ct, key],
                )
                .unwrap();
        };

        // (2) swap NONCE между строками (ciphertext остаются на местах) —
        // AEAD ловит: nonce+ct рассинхронизированы → тег не сходится.
        {
            let (na, ca) = read_row(&storage, "slot:a");
            let (nb, _cb) = read_row(&storage, "slot:b");
            write_row(&storage, "slot:a", &nb, &ca);
            assert!(
                storage.get("slot:a").is_err(),
                "nonce swap must be detected"
            );
            write_row(&storage, "slot:a", &na, &ca); // restore
            assert!(storage.get("slot:a").is_ok(), "restore must work");
        }

        // (3) cross-DB swap: вся строка (nonce+ct) из БД-B в БД-A.
        let (storage_b, _file_b) = test_storage();
        storage_b.put("slot:a", b"payload-from-db-b").unwrap();
        {
            let (na_b, ct_b) = read_row(&storage_b, "slot:a");
            write_row(&storage, "slot:a", &na_b, &ct_b);
            // Ключ БД-A ≠ ключ БД-B → даже при совпавшем AAD расшифровка
            // чужим ключом не сходится (else — universal decryption oracle).
            assert!(
                storage.get("slot:a").is_err(),
                "cross-db row transplant must fail"
            );
        }

        // (4) copy-attack: (nonce, ct) из slot:b копируется в slot:a
        // (тот же ключ БД, разные AAD) — AAD-binding ловит; текст ошибки
        // не содержит plaintext.
        {
            let (nb, cb) = read_row(&storage, "slot:b");
            write_row(&storage, "slot:a", &nb, &cb);
            let res = storage.get("slot:a");
            assert!(
                res.is_err(),
                "row copy to another slot must fail AAD binding"
            );
            if let Err(StorageError::Crypto(msg)) = &res {
                assert!(
                    !msg.to_lowercase().contains("payload"),
                    "error text must not leak plaintext"
                );
            }
        }

        // Целостность не-атакованной записи: slot:b читается со своим
        // plaintext'ом (атаки локализованы в slot:a).
        assert_eq!(storage.get("slot:b").unwrap(), Some(b"payload-b".to_vec()));
    }

    #[test]
    fn test_get_nonexistent() {
        let (storage, _file) = test_storage();
        assert_eq!(storage.get("missing").unwrap(), None);
    }

    #[test]
    fn test_put_overwrites() {
        let (storage, _file) = test_storage();
        storage.put("key", b"v1").unwrap();
        storage.put("key", b"v2").unwrap();
        assert_eq!(storage.get("key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_delete() {
        let (storage, _file) = test_storage();
        storage.put("temp", b"data").unwrap();
        assert!(storage.delete("temp").unwrap());
        assert_eq!(storage.get("temp").unwrap(), None);
    }

    #[test]
    fn test_list_keys() {
        let (storage, _file) = test_storage();
        storage.put("a", b"1").unwrap();
        storage.put("b", b"2").unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn test_len() {
        let (storage, _file) = test_storage();
        assert_eq!(storage.len().unwrap(), 0);
        storage.put("x", b"1").unwrap();
        storage.put("y", b"2").unwrap();
        assert_eq!(storage.len().unwrap(), 2);
    }

    #[test]
    fn malformed_nonce_length_fails_closed() {
        let (storage, _file) = test_storage();
        for nonce in [
            vec![0u8; 1],
            vec![0u8; NONCE_LEN - 1],
            vec![0u8; NONCE_LEN + 1],
        ] {
            storage
                .conn
                .execute(
                    "INSERT OR REPLACE INTO kv (key, nonce, ciphertext, created_at, updated_at)
                 VALUES ('bad-nonce', ?1, x'00', 0, 0)",
                    params![nonce],
                )
                .unwrap();
            let result = storage.get("bad-nonce");
            assert!(
                matches!(result, Err(StorageError::Crypto(_))),
                "nonce={}",
                nonce.len()
            );
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let file = NamedTempFile::new().unwrap();
        let key1 = generate_storage_key();
        let key2 = generate_storage_key();

        let storage1 = Storage::open(file.path(), &key1).unwrap();
        storage1.put("secret", b"data").unwrap();
        drop(storage1);

        let storage2 = Storage::open(file.path(), &key2).unwrap();
        match storage2.get("secret") {
            Err(StorageError::Crypto(_)) => {}
            Ok(_) => panic!("should fail with wrong key"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_empty_value() {
        let (storage, _file) = test_storage();
        storage.put("empty", b"").unwrap();
        assert_eq!(storage.get("empty").unwrap(), Some(vec![]));
    }

    #[test]
    fn test_large_value() {
        let (storage, _file) = test_storage();
        let big = vec![0xABu8; 65536];
        storage.put("big", &big).unwrap();
        assert_eq!(storage.get("big").unwrap(), Some(big));
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
    }
}
