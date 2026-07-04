//! # hop-store-sqlite
//!
//! A persistent [`Store`](hop_core::store::Store) backend for Hop, on SQLite via
//! `rusqlite` (bundled) — the decided backend in DESIGN.md §13.2. Survives
//! restarts, dedups across them, and supports the spray-and-wait copy mutations.
//!
//! Two tables: `bundles(id, data)` holds the currently-held bundles (postcard
//! encoded), and `seen(id)` is the dedup set — retained after a bundle is removed
//! so a re-offered duplicate is still rejected. The copy budget lives inside the
//! encoded `data` (re-encoded on mutation) so a read always reflects current state.
//!
//! Encryption at rest (F-25): available via the `sqlcipher` cargo feature + [`SqliteStore::open_keyed`].
//! The default build uses plain `bundled` SQLite (cleartext on disk — ratchet keys, hps content keys,
//! queued message bodies), so a plain-feature build must still rely on iOS file protection + the app
//! sandbox. Build with `--features sqlcipher` (SQLite + SQLCipher, vendored OpenSSL) and open the store
//! with a 32-byte key from the platform Keychain/Keystore to encrypt every page at rest (DESIGN.md §13.2).

use hop_core::bundle::{Bundle, BundleId};
use hop_core::store::{HaveSet, Store};
use rusqlite::{params, Connection};

/// Hard cap on how long a `seen` dedup row is retained, regardless of a bundle's claimed
/// `lifetime_ms` (F-07). The field is attacker-controlled (a `u32` ms, ~49 days max) and, for an
/// unsigned §39 private bundle, unauthenticated — so a flood of long-lived ids could bloat the
/// dedup set for weeks. We clamp the retained window to a week; a duplicate past that is re-accepted
/// (harmless — it re-floods and is re-deduped) but the table cannot be pinned open indefinitely.
const MAX_SEEN_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Row cap on the `seen` dedup table (F-07). Past this we evict the nearest-to-expiry rows so a
/// bundle flood can't grow it without bound. Generous enough that legitimate traffic never trips it.
const MAX_SEEN_ROWS: i64 = 200_000;

/// A SQLite-backed bundle store.
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Open (creating if needed) a store at `path`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::from_conn(Connection::open(path)?)
    }

    /// Open an ENCRYPTED store at `path`, keyed by a raw 32-byte `key` (F-25). The key is used
    /// directly (no passphrase KDF); the host derives + stores it in the platform Keychain/Keystore.
    /// Under the `sqlcipher` cargo feature this encrypts every page at rest (SQLCipher). Without that
    /// feature the `PRAGMA key` is silently ignored by plain SQLite, so build with `--features
    /// sqlcipher` for real at-rest encryption. An empty key opens unencrypted (same as `open`).
    pub fn open_keyed(path: &str, key: &[u8]) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        if !key.is_empty() {
            // SQLCipher raw-key form: `PRAGMA key = "x'<hex>'"` uses the bytes directly. Must run
            // BEFORE any table access (from_conn), which SQLCipher requires to derive the page cipher.
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
        }
        Self::from_conn(conn)
    }

    /// Open an ephemeral in-memory store (for tests).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> rusqlite::Result<Self> {
        // D7: schema/format version, tracked in SQLite's built-in `user_version`. Bump on any
        // incompatible on-disk change (table shape OR row encoding). v2 = the §39 wire change (F-06):
        // pre-v2 rows are a different postcard layout, so an old db is RESET rather than silently
        // misread. Pre-prod (iterate-freely), so a clean reset is acceptable; a real migration keyed
        // on the old `user_version` would go here. A fresh db (user_version 0) just adopts the current.
        const SCHEMA_VERSION: i64 = 2;
        let uv: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if uv != 0 && uv != SCHEMA_VERSION {
            eprintln!("hop-store-sqlite: on-disk schema v{uv} != v{SCHEMA_VERSION}; resetting store");
            conn.execute_batch(
                "DROP TABLE IF EXISTS bundles; DROP TABLE IF EXISTS seen; DROP TABLE IF EXISTS kv;",
            )?;
        }
        // Performance-critical: the node holds its single Mutex across every store write, so each
        // write's fsync stalls ALL node processing (link Noise handshakes, prekey gossip, sends).
        // The default journal_mode=DELETE + synchronous=FULL does an fsync per statement — under
        // multi-peer BLE load that fsync storm jams the serial executor and links never reach Up,
        // so prekeys never exchange and messages hang "Securing" forever. WAL + synchronous=NORMAL
        // keeps durability (survives app crash; only loses the last commits on an OS/power crash —
        // acceptable for a store-and-forward cache) while removing the per-write fsync. busy_timeout
        // lets a reader wait out a concurrent writer instead of erroring. (No-op on :memory: tests.)
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;",
        )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bundles (id BLOB PRIMARY KEY, data BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS seen (id BLOB PRIMARY KEY, expires_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
        )?;
        // D7: stamp the current schema/format version so a future incompatible bump is detected.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self { conn })
    }

    /// Keep the `seen` dedup table under [`MAX_SEEN_ROWS`] by evicting the nearest-to-expiry rows
    /// (F-07). Cheap: only runs the delete when the count is actually over the cap.
    fn enforce_seen_cap(&self) -> rusqlite::Result<()> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM seen", [], |r| r.get(0))?;
        if n > MAX_SEEN_ROWS {
            self.conn.execute(
                "DELETE FROM seen WHERE id IN \
                 (SELECT id FROM seen ORDER BY expires_at ASC LIMIT ?1)",
                params![n - MAX_SEEN_ROWS],
            )?;
        }
        Ok(())
    }

    fn write_data(&self, id: &BundleId, bundle: &Bundle) -> rusqlite::Result<()> {
        let data = bundle.to_bytes().map_err(to_sqlite_err)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO bundles (id, data) VALUES (?1, ?2)",
            params![&id[..], data],
        )?;
        Ok(())
    }
}

fn to_sqlite_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

impl Store for SqliteStore {
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        let id = bundle.id();
        if self.seen(&id) {
            return false; // dedup within the id's window
        }
        // Clamp the retained dedup window so an attacker-set (and, for private bundles,
        // unauthenticated) lifetime_ms can't pin a `seen` row open for weeks (F-07).
        let lifetime = (bundle.inner.lifetime_ms as u64).min(MAX_SEEN_LIFETIME_MS);
        let expires_at = now_ms.saturating_add(lifetime);
        let result = (|| -> rusqlite::Result<()> {
            self.conn.execute(
                "INSERT OR IGNORE INTO seen (id, expires_at) VALUES (?1, ?2)",
                params![&id[..], expires_at as i64],
            )?;
            self.enforce_seen_cap()?;
            self.write_data(&id, &bundle)
        })();
        result.is_ok()
    }

    fn get(&self, id: &BundleId) -> Option<Bundle> {
        self.conn
            .query_row(
                "SELECT data FROM bundles WHERE id = ?1",
                params![&id[..]],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .and_then(|data| Bundle::from_bytes(&data).ok())
    }

    fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
        let existing = self.get(id);
        let _ = self
            .conn
            .execute("DELETE FROM bundles WHERE id = ?1", params![&id[..]]);
        existing
    }

    fn seen(&self, id: &BundleId) -> bool {
        self.conn
            .query_row("SELECT 1 FROM seen WHERE id = ?1", params![&id[..]], |_| Ok(()))
            .is_ok()
    }

    fn contains(&self, id: &BundleId) -> bool {
        self.conn
            .query_row("SELECT 1 FROM bundles WHERE id = ?1", params![&id[..]], |_| Ok(()))
            .is_ok()
    }

    fn have(&self) -> HaveSet {
        let ids = (|| -> rusqlite::Result<Vec<BundleId>> {
            let mut stmt = self.conn.prepare("SELECT id FROM bundles")?;
            let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            let mut out = Vec::new();
            for r in rows {
                if let Ok(id) = <[u8; 32]>::try_from(r?.as_slice()) {
                    out.push(id);
                }
            }
            Ok(out)
        })()
        .unwrap_or_default();
        HaveSet { ids }
    }

    fn prune(&mut self, now_ms: u64) {
        let _ = self.conn.execute(
            "DELETE FROM bundles WHERE id IN (SELECT id FROM seen WHERE expires_at <= ?1)",
            params![now_ms as i64],
        );
        let _ = self
            .conn
            .execute("DELETE FROM seen WHERE expires_at <= ?1", params![now_ms as i64]);
    }

    fn split_copies(&mut self, id: &BundleId) -> u16 {
        let Some(mut bundle) = self.get(id) else {
            return 0;
        };
        let give = bundle.split_copies();
        if give > 0 {
            let _ = self.write_data(id, &bundle);
        }
        give
    }

    fn put_kv(&mut self, key: &str, value: Vec<u8>) {
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
            params![key, value],
        );
    }

    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        self.conn
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| r.get::<_, Vec<u8>>(0))
            .ok()
    }

    fn remove_kv(&mut self, key: &str) {
        let _ = self.conn.execute("DELETE FROM kv WHERE key = ?1", params![key]);
    }

    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        // `prefix%` with the LIKE wildcard; prefixes here are fixed ("session/"), no escaping.
        let pattern = format!("{prefix}%");
        let Ok(mut stmt) = self.conn.prepare("SELECT key, value FROM kv WHERE key LIKE ?1") else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![pattern], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        });
        match rows {
            Ok(it) => it.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn set_copies(&mut self, id: &BundleId, copies: u16) {
        if let Some(mut bundle) = self.get(id) {
            bundle.env.copies = copies;
            let _ = self.write_data(id, &bundle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::prelude::*;

    fn sample(copies: u16) -> Bundle {
        let from = Identity::generate();
        let to = Identity::generate();
        Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage { content_type: "t".into(), body: b"persist me".to_vec() },
            BundleOpts { copies, ..Default::default() },
        )
        .unwrap()
    }

    #[test]
    fn put_get_dedup_remove() {
        let mut s = SqliteStore::open_in_memory().unwrap();
        let b = sample(8);
        let id = b.id();

        assert!(s.put(b.clone(), 0));
        assert!(!s.put(b.clone(), 0), "duplicate rejected");
        assert!(s.seen(&id) && s.contains(&id));

        let got = s.get(&id).unwrap();
        got.verify().unwrap();
        assert_eq!(got, b);
        assert_eq!(s.have().ids, vec![id]);

        s.remove(&id);
        assert!(s.get(&id).is_none());
        assert!(!s.contains(&id));
        assert!(s.seen(&id), "seen is retained after removal for dedup");
        assert!(!s.put(b, 0), "a removed-but-seen bundle is not re-accepted");
    }

    #[test]
    fn copy_budget_mutations_persist() {
        let mut s = SqliteStore::open_in_memory().unwrap();
        let b = sample(8);
        let id = b.id();
        s.put(b, 0);

        assert_eq!(s.split_copies(&id), 4); // 8 -> keep 4, give 4
        assert_eq!(s.get(&id).unwrap().env.copies, 4);
        assert_eq!(s.split_copies(&id), 2); // 4 -> keep 2, give 2
        assert_eq!(s.get(&id).unwrap().env.copies, 2);

        s.set_copies(&id, 8); // retransmit reset
        assert_eq!(s.get(&id).unwrap().env.copies, 8);
    }

    #[test]
    fn survives_reopen() {
        let path = format!("{}/hop-sqlite-reopen-test.db", std::env::temp_dir().display());
        let _ = std::fs::remove_file(&path);

        let b = sample(8);
        let id = b.id();
        {
            let mut s = SqliteStore::open(&path).unwrap();
            s.put(b.clone(), 0);
        } // drop closes the connection

        let s = SqliteStore::open(&path).unwrap();
        let got = s.get(&id).expect("bundle persisted across reopen");
        assert_eq!(got, b);
        got.verify().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prune_closes_dedup_window() {
        let mut s = SqliteStore::open_in_memory().unwrap();
        let from = Identity::generate();
        let to = Identity::generate();
        let b = Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage { content_type: "t".into(), body: vec![1] },
            BundleOpts { lifetime_ms: 1_000, ..Default::default() },
        )
        .unwrap();
        let id = b.id();

        s.put(b.clone(), 0); // dedup window closes at 1000
        s.prune(500);
        assert!(s.seen(&id) && s.contains(&id));
        s.prune(2_000);
        assert!(!s.seen(&id) && !s.contains(&id), "window closed, entry pruned");
        assert!(s.put(b, 2_000), "re-accepted after window");
    }

    #[test]
    fn seen_lifetime_is_clamped_against_a_hostile_lifetime_ms() {
        // F-07: a bundle claiming a ~49-day lifetime must not pin its `seen` row open that long;
        // the retained window is clamped to MAX_SEEN_LIFETIME_MS (one week).
        let mut s = SqliteStore::open_in_memory().unwrap();
        let from = Identity::generate();
        let to = Identity::generate();
        let b = Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage { content_type: "t".into(), body: vec![1] },
            BundleOpts { lifetime_ms: u32::MAX, ..Default::default() }, // hostile: ~49 days
        )
        .unwrap();
        let id = b.id();
        s.put(b, 0);
        // Just past the clamp, the dedup row is gone (would still be present if lifetime_ms won).
        s.prune(MAX_SEEN_LIFETIME_MS + 1);
        assert!(!s.seen(&id), "seen row must be clamped to the max window, not the claimed lifetime");
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn sqlcipher_encrypts_at_rest() {
        // F-25: with the sqlcipher feature, a keyed store is unreadable without the key — proving the
        // pages are actually encrypted on disk (a plain or wrong-key open fails to even read the schema).
        let path = format!("{}/hop-sqlcipher-test.db", std::env::temp_dir().display());
        let _ = std::fs::remove_file(&path);
        let key = [7u8; 32];
        let b = sample(8);
        let id = b.id();
        {
            let mut s = SqliteStore::open_keyed(&path, &key).unwrap();
            assert!(s.put(b, 0));
        }
        assert!(SqliteStore::open(&path).is_err(), "plain (unkeyed) open of an encrypted db must fail");
        assert!(SqliteStore::open_keyed(&path, &[9u8; 32]).is_err(), "wrong key must fail");
        let s = SqliteStore::open_keyed(&path, &key).unwrap();
        assert!(s.contains(&id), "the right key decrypts and reads the data");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn incompatible_schema_version_resets_the_store() {
        // D7: a db stamped with an older schema version is reset on open, so old-encoding rows are
        // never silently misread. (A matching version leaves data intact — covered by survives_reopen.)
        let path = format!("{}/hop-sqlite-schema-test.db", std::env::temp_dir().display());
        let _ = std::fs::remove_file(&path);
        let b = sample(8);
        let id = b.id();
        {
            let mut s = SqliteStore::open(&path).unwrap();
            s.put(b, 0);
            // Simulate an older on-disk schema.
            s.conn.pragma_update(None, "user_version", 1i64).unwrap();
        }
        let s = SqliteStore::open(&path).unwrap();
        assert!(!s.contains(&id), "an incompatible-version db is reset (rows dropped)");
        assert!(!s.seen(&id), "seen table reset too");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drives_a_node_as_a_backend() {
        // The whole point: Node runs on the persistent store.
        let sender = Identity::generate();
        let you = Identity::generate();
        let bundle = Bundle::create(
            &sender,
            Destination::Device(you.address()),
            &you.address(),
            &Payload::PeerMessage { content_type: "t".into(), body: b"hi".to_vec() },
            BundleOpts::default(),
        )
        .unwrap();
        let bid = bundle.id();

        let mut node = Node::with_store(Identity::generate(), SqliteStore::open_in_memory().unwrap());
        node.submit(bundle);
        assert!(node.store.contains(&bid), "submitted bundle is in the sqlite store");
    }
}
