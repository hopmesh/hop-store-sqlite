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
use zeroize::Zeroize;

/// stores-12: format the raw key bytes as lowercase hex into a heap `String` that is zeroized on
/// drop. The at-rest SQLCipher key would otherwise linger in an unzeroized allocation for the
/// process lifetime; wrapping it means the hex spelling is wiped as soon as it goes out of scope.
struct HexKey(String);

impl HexKey {
    fn new(key: &[u8]) -> Self {
        let mut hex = String::with_capacity(key.len() * 2);
        for b in key {
            // Manual nibble->hex so we never route the bytes through a throwaway `format!`
            // allocation that we couldn't zeroize.
            const NIBBLES: &[u8; 16] = b"0123456789abcdef";
            hex.push(NIBBLES[(b >> 4) as usize] as char);
            hex.push(NIBBLES[(b & 0x0f) as usize] as char);
        }
        HexKey(hex)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for HexKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

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
    /// stores-10: in-memory count of `seen` rows so `put` does not run `SELECT COUNT(*)` (a full
    /// table scan) on every insert under the node Mutex. Seeded once at open, then kept in step with
    /// every insert/evict/prune.
    seen_rows: std::cell::Cell<i64>,
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
            // stores-12: both the hex spelling and the assembled PRAGMA text are zeroized after use.
            let hex = HexKey::new(key);
            let mut pragma = format!("PRAGMA key = \"x'{}'\";", hex.as_str());
            let res = conn.execute_batch(&pragma);
            pragma.zeroize();
            res?;
        }
        Self::from_conn(conn)
    }

    /// True iff the file at `path` opens as an UNENCRYPTED SQLite database (its header reads as a
    /// plain db). Used to tell "existing plaintext db, we now have a key" (migrate) apart from
    /// "wrong key / genuine corruption" (fail closed) so a keyed open never silently wipes state.
    /// Without the `sqlcipher` feature `PRAGMA key` is a no-op, so a keyed open of a plain file
    /// already succeeds and this path is not exercised.
    pub fn opens_as_plaintext(path: &str) -> bool {
        if !std::path::Path::new(path).exists() {
            return false;
        }
        // A plain (unkeyed) open that can read the schema means the bytes are an unencrypted db.
        Connection::open(path)
            .and_then(|c| {
                c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?;
                Ok(())
            })
            .is_ok()
    }

    /// Migrate an existing PLAINTEXT db at `path` to a SQLCipher-encrypted db keyed with `key`,
    /// in place, via `sqlcipher_export` (the standard SQLCipher plaintext->encrypted recipe): open
    /// the plain db, ATTACH a fresh keyed sidecar, export into it, then atomically replace the
    /// original. Preserves all rows (sessions, prekeys, queued sends) instead of wiping them.
    #[cfg(feature = "sqlcipher")]
    pub fn migrate_plaintext_to_keyed(path: &str, key: &[u8]) -> rusqlite::Result<Self> {
        if key.is_empty() {
            return Self::open_keyed(path, key); // nothing to encrypt to
        }
        let sidecar = format!("{path}.migrating");
        let _ = std::fs::remove_file(&sidecar);
        // stores-r2-02: the sidecar itself may also carry stale WAL/SHM from a crashed prior attempt.
        let _ = std::fs::remove_file(format!("{sidecar}-wal"));
        let _ = std::fs::remove_file(format!("{sidecar}-shm"));
        // stores-12: hex spelling zeroized on drop; the assembled ATTACH batch is zeroized after use.
        let hex = HexKey::new(key);
        {
            let conn = Connection::open(path)?; // plaintext source
                                                // stores-r2-02: the plaintext db was created via from_conn, which sets journal_mode=WAL,
                                                // so `{path}-wal`/`{path}-shm` sidecars exist beside it. If we rename only the main file
                                                // over the destination, those plaintext WAL/SHM files are left orphaned next to the new
                                                // SQLCipher db; when open_keyed re-enables WAL, SQLite can try to recover against a -wal
                                                // that belongs to a DIFFERENT (unencrypted) database -> open failure or corruption on the
                                                // exact already-installed devices this migration exists to protect. Checkpoint and switch
                                                // the source to journal_mode=DELETE so it folds the WAL back into the main file and drops
                                                // the sidecars BEFORE we export + rename. (No-op if the source was never WAL.)
            conn.execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE);
                 PRAGMA journal_mode=DELETE;",
            )?;
            let mut batch = format!(
                "ATTACH DATABASE '{sidecar}' AS enc KEY \"x'{}'\";\
                 SELECT sqlcipher_export('enc');\
                 DETACH DATABASE enc;",
                hex.as_str()
            );
            let res = conn.execute_batch(&batch);
            batch.zeroize();
            res?;
        } // conn dropped -> sidecar flushed + closed
          // Atomically replace the plaintext original with the encrypted sidecar.
        std::fs::rename(&sidecar, path).map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                Some(format!("sqlcipher migrate rename failed: {e}")),
            )
        })?;
        // stores-r2-02: belt-and-suspenders. Remove any plaintext WAL/SHM that lingered (e.g. the
        // journal_mode switch was a no-op on an older SQLite, or a sidecar the checkpoint didn't
        // fold). These belong to the now-gone plaintext db; the new SQLCipher db will create its own.
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
        Self::open_keyed(path, key)
    }

    /// Open an ephemeral in-memory store (for tests).
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> rusqlite::Result<Self> {
        // D7: schema/format version, tracked in SQLite's built-in `user_version`. Bump on any
        // incompatible on-disk change (table shape OR row encoding). A fresh db (user_version 0)
        // just adopts the current version.
        //
        // stores-06: migrate keyed on the OLD `user_version` instead of amnesia-ing the whole store.
        // The only incompatible bump to date (v1 -> v2, the §39 wire change F-06) re-encodes the
        // `bundles`/`seen` rows but does NOT touch the `kv` schema. `kv` holds the device's durable,
        // wire-format-INDEPENDENT state: forward-secret ratchet sessions, prekey secrets, the queued
        // send buffer, and hosted hps keys. Dropping those forced a full re-secure with every peer
        // (historically the fragile path) and lost queued sends on every upgrade. So we drop only the
        // wire-format-dependent tables and PRESERVE `kv`. An unrecognized (future/older) version we
        // can't migrate still falls back to a clean reset rather than risk a silent misread.
        const SCHEMA_VERSION: i64 = 2;
        let uv: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if uv != 0 && uv != SCHEMA_VERSION {
            if uv == 1 {
                // v1 -> v2: only the bundle/seen row encoding changed; keep `kv` intact.
                eprintln!(
                    "hop-store-sqlite: migrating schema v{uv} -> v{SCHEMA_VERSION} \
                     (re-encoding bundles/seen; preserving kv sessions/queued sends)"
                );
                conn.execute_batch("DROP TABLE IF EXISTS bundles; DROP TABLE IF EXISTS seen;")?;
            } else {
                // No migration known for this version pair: reset rather than risk misreading rows.
                eprintln!(
                    "hop-store-sqlite: on-disk schema v{uv} has no migration to v{SCHEMA_VERSION}; \
                     resetting store"
                );
                conn.execute_batch(
                    "DROP TABLE IF EXISTS bundles; DROP TABLE IF EXISTS seen; DROP TABLE IF EXISTS kv;",
                )?;
            }
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
             CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             -- stores-10: index expires_at so the cap-eviction ORDER BY and both prune predicates
             -- (WHERE expires_at <= ?) are index range scans, not full-table scans under the Mutex.
             CREATE INDEX IF NOT EXISTS idx_seen_expires_at ON seen (expires_at);",
        )?;
        // D7: stamp the current schema/format version so a future incompatible bump is detected.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        // stores-10: seed the in-memory row count once (the only COUNT(*) we run) so puts never scan.
        let seen_rows: i64 = conn.query_row("SELECT COUNT(*) FROM seen", [], |r| r.get(0))?;
        Ok(Self {
            conn,
            seen_rows: std::cell::Cell::new(seen_rows),
        })
    }

    /// Keep the `seen` dedup table under [`MAX_SEEN_ROWS`] by evicting the nearest-to-expiry rows
    /// (F-07). Cheap: only runs the delete when the count is actually over the cap. Any held bundle
    /// for an evicted id is deleted in the same step (stores-04): prune deletes bundles only via the
    /// `seen` join, so an evicted seen row would otherwise orphan its bundle past its lifetime.
    fn enforce_seen_cap(&self) -> rusqlite::Result<()> {
        // stores-10: gate on the tracked count so the common case (under the cap) does no query at
        // all - the previous per-put `SELECT COUNT(*)` was a full-table scan under the node Mutex.
        let n = self.seen_rows.get();
        if n > MAX_SEEN_ROWS {
            // Materialize the victim ids once so we delete the same set from both tables. The
            // ORDER BY now rides idx_seen_expires_at instead of scanning + sorting the whole table.
            let victims: Vec<Vec<u8>> = {
                let mut stmt = self
                    .conn
                    .prepare("SELECT id FROM seen ORDER BY expires_at ASC LIMIT ?1")?;
                let rows =
                    stmt.query_map(params![n - MAX_SEEN_ROWS], |r| r.get::<_, Vec<u8>>(0))?;
                rows.filter_map(|r| r.ok()).collect()
            };
            // stores-r2-04: evict from `bundles` and `seen` inside ONE transaction, matching put()'s
            // atomicity. Previously each victim did two separate un-enclosed DELETEs and bumped
            // `seen_rows` only after the seen delete; a mid-loop failure (bundles deleted, seen delete
            // errors, or vice versa) drifted the tracked count from the table and could orphan a
            // held bundle without its seen row (or a seen row without its bundle) until reopen
            // re-seeded the count. Now either every victim is removed from both tables or none is, and
            // `seen_rows` is decremented only from the COMMITTED seen-delete count. `unchecked_`
            // because enforce runs behind `&self` (interior-mutable count); the node Mutex serializes
            // all store access, so there is no concurrent writer on this single connection.
            let tx = self.conn.unchecked_transaction()?;
            let mut removed_total: i64 = 0;
            for id in &victims {
                tx.execute("DELETE FROM bundles WHERE id = ?1", params![id])?;
                removed_total += tx.execute("DELETE FROM seen WHERE id = ?1", params![id])? as i64;
            }
            tx.commit()?;
            self.seen_rows.set(self.seen_rows.get() - removed_total);
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
        // Transactional (stores-03): the seen row and the bundle write must commit together. Without
        // this, a failed bundle write (disk full, encode error) would leave the id poisoned in `seen`
        // for up to a week, permanently rejecting every re-offer of a bundle we never actually stored.
        let result = (|| -> rusqlite::Result<usize> {
            let tx = self.conn.transaction()?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO seen (id, expires_at) VALUES (?1, ?2)",
                params![&id[..], expires_at as i64],
            )?;
            let data = bundle.to_bytes().map_err(to_sqlite_err)?;
            tx.execute(
                "INSERT OR REPLACE INTO bundles (id, data) VALUES (?1, ?2)",
                params![&id[..], data],
            )?;
            tx.commit()?;
            Ok(inserted)
        })();
        // stores-10: keep the tracked count in step with the actual seen insert (0 if the id was
        // already present) so cap enforcement never runs a COUNT(*). Only bump on a committed tx.
        if let Ok(inserted) = result {
            self.seen_rows.set(self.seen_rows.get() + inserted as i64);
        }
        // Cap enforcement is a separate best-effort maintenance step outside the put transaction.
        let _ = self.enforce_seen_cap();
        result.is_ok()
    }

    fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        // relay-A audit: re-hold an evicted-but-durable bundle even though its `seen` row survives (a
        // mailbox re-pull / handoff re-ingest). Same transactional write as put, but WITHOUT the seen
        // gate: INSERT OR IGNORE keeps the existing dedup expiry, INSERT OR REPLACE re-holds the bundle.
        let id = bundle.id();
        let lifetime = (bundle.inner.lifetime_ms as u64).min(MAX_SEEN_LIFETIME_MS);
        let expires_at = now_ms.saturating_add(lifetime);
        let result = (|| -> rusqlite::Result<usize> {
            let tx = self.conn.transaction()?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO seen (id, expires_at) VALUES (?1, ?2)",
                params![&id[..], expires_at as i64],
            )?;
            let data = bundle.to_bytes().map_err(to_sqlite_err)?;
            tx.execute(
                "INSERT OR REPLACE INTO bundles (id, data) VALUES (?1, ?2)",
                params![&id[..], data],
            )?;
            tx.commit()?;
            Ok(inserted)
        })();
        if let Ok(inserted) = result {
            self.seen_rows.set(self.seen_rows.get() + inserted as i64);
        }
        let _ = self.enforce_seen_cap();
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
            .query_row("SELECT 1 FROM seen WHERE id = ?1", params![&id[..]], |_| {
                Ok(())
            })
            .is_ok()
    }

    fn contains(&self, id: &BundleId) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM bundles WHERE id = ?1",
                params![&id[..]],
                |_| Ok(()),
            )
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
        // stores-10: both deletes now ride idx_seen_expires_at; keep the tracked count in step.
        if let Ok(removed) = self.conn.execute(
            "DELETE FROM seen WHERE expires_at <= ?1",
            params![now_ms as i64],
        ) {
            self.seen_rows.set(self.seen_rows.get() - removed as i64);
        }
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
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .ok()
    }

    fn remove_kv(&mut self, key: &str) {
        let _ = self
            .conn
            .execute("DELETE FROM kv WHERE key = ?1", params![key]);
    }

    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        // `prefix%` with the LIKE wildcard; prefixes here are fixed ("session/"), no escaping.
        let pattern = format!("{prefix}%");
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT key, value FROM kv WHERE key LIKE ?1")
        else {
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

    fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
        // stores-r3-01: the durable, receiver-anchored dedup deadline for `id` (the clamped
        // now+lifetime stamped at put time). Callers use this as the authoritative expiry for a
        // handoff/spool re-mirror instead of the sender's advisory created_at.
        self.conn
            .query_row(
                "SELECT expires_at FROM seen WHERE id = ?1",
                params![&id[..]],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .map(|e| e as u64)
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
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"persist me".to_vec(),
            },
            BundleOpts {
                copies,
                ..Default::default()
            },
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
        let path = format!(
            "{}/hop-sqlite-reopen-test.db",
            std::env::temp_dir().display()
        );
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
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: vec![1],
            },
            BundleOpts {
                lifetime_ms: 1_000,
                ..Default::default()
            },
        )
        .unwrap();
        let id = b.id();

        s.put(b.clone(), 0); // dedup window closes at 1000
        s.prune(500);
        assert!(s.seen(&id) && s.contains(&id));
        s.prune(2_000);
        assert!(
            !s.seen(&id) && !s.contains(&id),
            "window closed, entry pruned"
        );
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
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: vec![1],
            },
            BundleOpts {
                lifetime_ms: u32::MAX,
                ..Default::default()
            }, // hostile: ~49 days
        )
        .unwrap();
        let id = b.id();
        s.put(b, 0);
        // Just past the clamp, the dedup row is gone (would still be present if lifetime_ms won).
        s.prune(MAX_SEEN_LIFETIME_MS + 1);
        assert!(
            !s.seen(&id),
            "seen row must be clamped to the max window, not the claimed lifetime"
        );
    }

    #[test]
    fn seen_cap_evicts_bundle_with_its_seen_row() {
        // stores-04: when the seen cap evicts a row, its held bundle must go too, or prune (which
        // joins on seen) can never reclaim it and it outlives its lifetime on disk.
        let mut s = SqliteStore::open_in_memory().unwrap();
        // Insert one real held bundle with a near expiry so it is the eviction target.
        let b = sample(8);
        let id = b.id();
        s.put(b, 0);
        // Directly stuff the seen table past the cap with far-future expiries so our real bundle's
        // seen row (expiry = default lifetime) is among the nearest-to-expiry and gets evicted.
        {
            let tx = s.conn.transaction().unwrap();
            for i in 0..(MAX_SEEN_ROWS + 10) {
                let mut fake = [0u8; 32];
                fake[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                fake[31] = 0xAA; // avoid colliding with the real id namespace
                tx.execute(
                    "INSERT OR IGNORE INTO seen (id, expires_at) VALUES (?1, ?2)",
                    params![&fake[..], i64::MAX],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        // The direct INSERTs above bypass put()'s tracked count; re-seed it from the table so the
        // cap gate reflects the rows we just stuffed in (matches the from_conn seed at open time).
        s.seen_rows.set(
            s.conn
                .query_row("SELECT COUNT(*) FROM seen", [], |r| r.get::<_, i64>(0))
                .unwrap(),
        );
        s.enforce_seen_cap().unwrap();
        // The real bundle's seen row (nearest expiry) was evicted; its held bundle must be gone too.
        assert!(!s.seen(&id), "seen row evicted under the cap");
        assert!(
            !s.contains(&id),
            "held bundle must be evicted with its seen row, not orphaned"
        );
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
        assert!(
            SqliteStore::open(&path).is_err(),
            "plain (unkeyed) open of an encrypted db must fail"
        );
        assert!(
            SqliteStore::open_keyed(&path, &[9u8; 32]).is_err(),
            "wrong key must fail"
        );
        let s = SqliteStore::open_keyed(&path, &key).unwrap();
        assert!(s.contains(&id), "the right key decrypts and reads the data");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn plaintext_db_migrates_to_keyed_without_losing_data() {
        // android-01: an existing PLAINTEXT hop.db plus a newly-supplied key must migrate in place
        // (plaintext -> SQLCipher) preserving every row, never wipe. Proves the recovery path the
        // config-divergence fix relies on for already-installed devices.
        let path = format!("{}/hop-migrate-test.db", std::env::temp_dir().display());
        let _ = std::fs::remove_file(&path);
        let key = [5u8; 32];
        let b = sample(11);
        let id = b.id();
        {
            let mut plain = SqliteStore::open(&path).unwrap(); // unencrypted, with data
            assert!(plain.put(b, 0));
        }
        assert!(
            SqliteStore::opens_as_plaintext(&path),
            "starts as a plain db"
        );
        let migrated = SqliteStore::migrate_plaintext_to_keyed(&path, &key).unwrap();
        assert!(migrated.contains(&id), "data survives the migration");
        assert!(
            SqliteStore::open(&path).is_err(),
            "after migration a plain open fails — it is now SQLCipher-encrypted"
        );
        assert!(
            !SqliteStore::opens_as_plaintext(&path),
            "no longer readable as plaintext"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn v1_to_v2_migration_drops_bundles_but_preserves_kv() {
        // stores-06: a v1 db migrated to v2 re-encodes bundles/seen (the §39 wire change) but must
        // PRESERVE `kv` (ratchet sessions, prekey secrets, queued sends), not amnesia the device.
        let path = format!(
            "{}/hop-sqlite-schema-test.db",
            std::env::temp_dir().display()
        );
        let _ = std::fs::remove_file(&path);
        let b = sample(8);
        let id = b.id();
        {
            let mut s = SqliteStore::open(&path).unwrap();
            s.put(b, 0);
            s.put_kv("session/peerX", b"ratchet-state".to_vec()); // durable device state
                                                                  // Simulate an older (v1) on-disk schema.
            s.conn.pragma_update(None, "user_version", 1i64).unwrap();
        }
        let s = SqliteStore::open(&path).unwrap();
        assert!(
            !s.contains(&id),
            "wire-format-dependent bundle rows are dropped on the v1->v2 migration"
        );
        assert!(!s.seen(&id), "seen table dropped too (re-encoded)");
        assert_eq!(
            s.get_kv("session/peerX"),
            Some(b"ratchet-state".to_vec()),
            "kv (sessions/queued sends) survives the migration"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_schema_version_resets_the_whole_store() {
        // stores-06: a version pair with no known migration still falls back to a clean reset (kv
        // included) rather than risk silently misreading rows.
        let path = format!(
            "{}/hop-sqlite-schema-unknown-test.db",
            std::env::temp_dir().display()
        );
        let _ = std::fs::remove_file(&path);
        {
            let mut s = SqliteStore::open(&path).unwrap();
            s.put_kv("session/peerX", b"ratchet-state".to_vec());
            // A version we have no migration for.
            s.conn.pragma_update(None, "user_version", 99i64).unwrap();
        }
        let s = SqliteStore::open(&path).unwrap();
        assert_eq!(
            s.get_kv("session/peerX"),
            None,
            "an unknown-version db is fully reset (kv dropped)"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tracked_seen_count_stays_in_step_with_the_table() {
        // stores-10: the in-memory seen_rows count must match COUNT(*) across put (new + dup),
        // prune, and reopen - it is what gates cap enforcement without a per-put full scan.
        let path = format!(
            "{}/hop-sqlite-count-test.db",
            std::env::temp_dir().display()
        );
        let _ = std::fs::remove_file(&path);
        let true_count = |s: &SqliteStore| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM seen", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        {
            let mut s = SqliteStore::open(&path).unwrap();
            assert_eq!(s.seen_rows.get(), 0);

            let a = sample(4);
            let a_bundle = a.clone();
            s.put(a, 0);
            assert_eq!(s.seen_rows.get(), 1);
            // A duplicate does not bump the count (INSERT OR IGNORE inserted 0 rows).
            s.put(a_bundle, 0);
            assert_eq!(s.seen_rows.get(), 1);
            assert_eq!(s.seen_rows.get(), true_count(&s));

            // A short-lived bundle we can prune out.
            let from = Identity::generate();
            let to = Identity::generate();
            let short = Bundle::create(
                &from,
                Destination::Device(to.address()),
                &to.address(),
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: vec![9],
                },
                BundleOpts {
                    lifetime_ms: 1_000,
                    ..Default::default()
                },
            )
            .unwrap();
            s.put(short, 0);
            assert_eq!(s.seen_rows.get(), 2);
            s.prune(2_000); // drops the short-lived seen row only
            assert_eq!(s.seen_rows.get(), 1);
            assert_eq!(s.seen_rows.get(), true_count(&s));
        }
        // Reopen re-seeds the count from the table (the one COUNT(*) we ever run).
        let s = SqliteStore::open(&path).unwrap();
        assert_eq!(s.seen_rows.get(), 1);
        assert_eq!(s.seen_rows.get(), true_count(&s));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn seen_expires_at_index_exists() {
        // stores-10: the expires_at index must be created so prune predicates and the cap-eviction
        // ORDER BY are index scans, not full-table scans under the node Mutex.
        let s = SqliteStore::open_in_memory().unwrap();
        let has_index: bool = s
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_seen_expires_at'",
                [],
                |_| Ok(()),
            )
            .is_ok();
        assert!(has_index, "idx_seen_expires_at must exist");
    }

    #[test]
    fn hex_key_wipes_the_backing_buffer() {
        // stores-12: the hex spelling of the at-rest key must be zeroized, not left lingering in a
        // heap allocation. We drive the exact wipe that Drop performs (String::zeroize) in place,
        // while the allocation is still owned by us, and read the SAME backing buffer through a raw
        // pointer captured before the wipe. This proves the volatile zeroing actually cleared the
        // bytes, without the UB of reading a freed allocation.
        let key = [0xABu8; 32];
        let mut hex = HexKey::new(&key);
        assert_eq!(hex.as_str(), "ab".repeat(32));
        let ptr = hex.0.as_ptr();
        let len = hex.0.len();
        hex.0.zeroize(); // same call the Drop impl makes; buffer stays allocated (owned by us)
                         // Safe: `hex` (and thus its backing allocation) is still alive for this read.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "hex key material must be zeroized, found non-zero bytes"
        );
        // And the exact same wipe happens automatically on drop.
        drop(hex);
    }

    #[test]
    fn seen_cap_eviction_keeps_tracked_count_in_step_and_never_orphans() {
        // stores-r2-04: the cap eviction now runs its two-table DELETEs inside ONE transaction.
        // After it runs, the tracked seen_rows MUST equal COUNT(*) (no drift), and no held bundle may
        // be left without its seen row (nor a seen row without its bundle). Previously the two DELETEs
        // were un-enclosed and seen_rows was bumped only after the seen delete, so a mid-loop failure
        // could drift the count and orphan a bundle; this asserts the transactional invariant.
        let mut s = SqliteStore::open_in_memory().unwrap();
        // A handful of REAL held bundles with the default (near) expiry (the eviction targets).
        let mut real_ids = Vec::new();
        for _ in 0..5 {
            let b = sample(8);
            real_ids.push(b.id());
            s.put(b, 0);
        }
        // Stuff the seen table well past the cap with far-future expiries so the real bundles (nearer
        // expiry) are the eviction victims.
        {
            let tx = s.conn.transaction().unwrap();
            for i in 0..(MAX_SEEN_ROWS + 20) {
                let mut fake = [0u8; 32];
                fake[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                fake[31] = 0xBB;
                tx.execute(
                    "INSERT OR IGNORE INTO seen (id, expires_at) VALUES (?1, ?2)",
                    params![&fake[..], i64::MAX],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        // Re-seed the tracked count from the table (the direct INSERTs bypass put()'s bump).
        let true_count = |s: &SqliteStore| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM seen", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        s.seen_rows.set(true_count(&s));

        s.enforce_seen_cap().unwrap();

        // Invariant 1: the tracked count exactly matches the table after the transactional eviction.
        assert_eq!(
            s.seen_rows.get(),
            true_count(&s),
            "tracked seen_rows must equal COUNT(*) after a transactional eviction (no drift)"
        );
        assert_eq!(
            true_count(&s),
            MAX_SEEN_ROWS,
            "seen table trimmed back to exactly the cap"
        );
        // Invariant 2: no held bundle is orphaned (every remaining held id still has a seen row).
        let orphans: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM bundles b LEFT JOIN seen s ON b.id = s.id WHERE s.id IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "no held bundle left without its seen row");
        // The real (near-expiry) bundles were the victims: gone from BOTH tables together.
        for id in &real_ids {
            assert!(!s.seen(id), "victim seen row evicted");
            assert!(
                !s.contains(id),
                "victim held bundle evicted with its seen row"
            );
        }
    }

    #[test]
    fn seen_cap_eviction_is_atomic_across_a_mid_loop_failure() {
        // stores-r2-04 (the actual before/after): inject a failure on the SECOND (seen) DELETE so a
        // victim's bundle DELETE lands but its seen DELETE errors mid-loop. The OLD code ran the two
        // DELETEs OUTSIDE a transaction and bumped seen_rows only after the seen delete, so this left
        // an orphaned bundle (deleted from `bundles`, still in `seen`) AND drifted the tracked count.
        // The FIX wraps the loop in one transaction, so the failure rolls the bundle DELETE back too:
        // no orphan, and seen_rows stays in step with the (unchanged) table.
        let mut s = SqliteStore::open_in_memory().unwrap();
        let mut real_ids = Vec::new();
        for _ in 0..3 {
            let b = sample(8);
            real_ids.push(b.id());
            s.put(b, 0);
        }
        {
            let tx = s.conn.transaction().unwrap();
            for i in 0..(MAX_SEEN_ROWS + 10) {
                let mut fake = [0u8; 32];
                fake[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                fake[31] = 0xCC;
                tx.execute(
                    "INSERT OR IGNORE INTO seen (id, expires_at) VALUES (?1, ?2)",
                    params![&fake[..], i64::MAX],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let true_count = |s: &SqliteStore| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM seen", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        s.seen_rows.set(true_count(&s));
        let count_before = true_count(&s);
        let held_before: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM bundles", [], |r| r.get(0))
            .unwrap();

        // Fault injection: a trigger that aborts every DELETE FROM seen. With a single enclosing
        // transaction the whole eviction (including the bundles DELETE) rolls back on this error.
        s.conn
            .execute_batch(
                "CREATE TRIGGER fail_seen_delete BEFORE DELETE ON seen \
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();

        let res = s.enforce_seen_cap();
        assert!(res.is_err(), "the injected seen-delete failure surfaces");

        // Remove the trigger so our assertions can read freely.
        s.conn
            .execute_batch("DROP TRIGGER fail_seen_delete;")
            .unwrap();

        // Atomicity: the failed eviction rolled back entirely, so table counts are UNCHANGED and no
        // bundle was orphaned and the tracked count did not drift from the table.
        assert_eq!(
            true_count(&s),
            count_before,
            "seen count unchanged: the transaction rolled back the whole eviction"
        );
        let held_after: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM bundles", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            held_after, held_before,
            "no bundle DELETE leaked: bundles table unchanged after the rolled-back eviction"
        );
        let orphans: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM bundles b LEFT JOIN seen s ON b.id = s.id WHERE s.id IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            orphans, 0,
            "no orphaned held bundle after the failed eviction"
        );
        for id in &real_ids {
            assert!(s.contains(id), "victim bundle preserved by the rollback");
            assert!(s.seen(id), "victim seen row preserved by the rollback");
        }
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn migration_folds_and_clears_a_lingering_plaintext_wal() {
        // stores-r2-02: the plaintext db runs in journal_mode=WAL (from_conn), so a device that was
        // killed before a checkpoint leaves a REAL plaintext `-wal` with committed frames NOT yet
        // folded into the main file, plus a `-shm`. The old migration opened the plaintext source,
        // exported the MAIN FILE ONLY (missing the WAL-resident rows), and renamed just the main db
        // over the destination, leaving the plaintext `-wal`/`-shm` orphaned next to the new
        // SQLCipher db, where open_keyed re-enabling WAL can try to recover against a foreign WAL.
        //
        // The fix checkpoints + switches the source to journal_mode=DELETE before export, so the
        // WAL-resident rows are folded in (captured by the encrypted export) and the sidecars are
        // gone. This test creates that exact lingering-WAL state (a forgotten connection with
        // autocheckpoint off) and proves both: (a) the WAL-only row survives into the encrypted db,
        // and (b) no plaintext sidecar with real frames is left behind.
        use rusqlite::Connection;
        let tmp = std::env::temp_dir();
        // Source db (where we build the lingering-WAL state) and the test target we migrate. We build
        // the state on `src`, then COPY the three files to `path` so the target has a real plaintext
        // WAL on disk with NO process holding an OS lock (mirrors a device snapshot after a crash).
        let src = format!("{}/hop-migrate-lingering-src.db", tmp.display());
        let path = format!("{}/hop-migrate-lingering-wal-test.db", tmp.display());
        let cleanup = |base: &str| {
            for suf in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{base}{suf}"));
            }
        };
        cleanup(&src);
        cleanup(&path);
        let wal = format!("{path}-wal");
        let shm = format!("{path}-shm");
        let key = [3u8; 32];
        let b = sample(9);
        let id = b.id();
        {
            let mut plain = SqliteStore::open(&src).unwrap();
            assert!(plain.put(b, 0)); // lands in the main file
        }
        // Raw connection: WAL, no autocheckpoint, write a kv row, then LEAK the connection so it never
        // checkpoints. The row now lives only in `{src}-wal`.
        {
            let raw = Connection::open(&src).unwrap();
            raw.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;",
            )
            .unwrap();
            raw.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                params!["session/wal-resident", &b"secret-ratchet-in-the-wal"[..]],
            )
            .unwrap();
            std::mem::forget(raw); // no clean close -> WAL frames persist on disk for `src`
        }
        // Snapshot the three files onto the test target (releasing any lock, like process death would).
        std::fs::copy(&src, &path).unwrap();
        std::fs::copy(format!("{src}-wal"), &wal).unwrap();
        let _ = std::fs::copy(format!("{src}-shm"), &shm); // -shm may be absent; fine
        assert!(
            std::fs::metadata(&wal)
                .map(|m| m.len() > 0)
                .unwrap_or(false),
            "a real plaintext WAL with frames lingers on the target before migration"
        );

        let migrated = SqliteStore::migrate_plaintext_to_keyed(&path, &key).unwrap();
        // (a) both the main-file bundle AND the WAL-resident kv row are captured in the encrypted db.
        assert!(
            migrated.contains(&id),
            "main-file bundle survives the migration"
        );
        assert_eq!(
            migrated.get_kv("session/wal-resident"),
            Some(b"secret-ratchet-in-the-wal".to_vec()),
            "the WAL-resident row was folded in and captured by the encrypted export"
        );
        drop(migrated);

        // (b) no plaintext sidecar with the WAL-resident secret survives beside the encrypted db.
        for p in [&wal, &shm] {
            if let Ok(bytes) = std::fs::read(p) {
                assert!(
                    !bytes
                        .windows(b"secret-ratchet-in-the-wal".len())
                        .any(|w| w == b"secret-ratchet-in-the-wal"),
                    "plaintext WAL-resident secret must not linger in sidecar {p}"
                );
            }
        }
        // And the encrypted db reopens cleanly with the key (no foreign-WAL recovery failure).
        let reopened = SqliteStore::open_keyed(&path, &key).unwrap();
        assert!(reopened.contains(&id), "keyed reopen reads cleanly");
        assert!(
            !SqliteStore::opens_as_plaintext(&path),
            "db is genuinely SQLCipher-encrypted"
        );
        drop(reopened);
        cleanup(&src);
        cleanup(&path);
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
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let bid = bundle.id();

        let mut node =
            Node::with_store(Identity::generate(), SqliteStore::open_in_memory().unwrap());
        node.submit(bundle);
        assert!(
            node.store.contains(&bid),
            "submitted bundle is in the sqlite store"
        );
    }
}
