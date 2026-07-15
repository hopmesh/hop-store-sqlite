<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-store-sqlite</h1>

<p align="center">
  <b>Persistence for a Hop node, on SQLite.</b><br>
  A durable <code>Store</code> backend for <a href="https://hopme.sh">Hop</a>, with SQLCipher encryption at rest.
</p>

<p align="center">
  <a href="https://crates.io/crates/hop-store-sqlite"><img src="https://img.shields.io/crates/v/hop-store-sqlite?color=dea584&label=crates.io" alt="crates.io"></a>
  <img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-3ddc84" alt="license">
  <img src="https://img.shields.io/badge/rust-2021-dea584" alt="rust 2021">
</p>

---

Hop is a **delay-tolerant mesh**: end-to-end encrypted datagrams that hop device to device, over BLE,
Wi-Fi, and the internet, until they reach the person you meant. Held, never dropped.

`hop-store-sqlite` is one implementation of `hop-core`'s `Store` trait: the held-bundle mailbox and the
dedup set on SQLite via `rusqlite`. It survives restarts, dedups across them, and supports the
spray-and-wait copy budget. It's what a device or a self-hosted node keeps its state in.

## Install

```toml
[dependencies]
hop-store-sqlite = "0.0"
```

## Use it

Hand a store to a node and you have durable state:

```rust
use hop_core::prelude::*;
use hop_store_sqlite::SqliteStore;

let store = SqliteStore::open("hop.db")?;
let mut node = Node::with_store(Identity::generate(), store);
```

Encrypt every page at rest (SQLCipher) with a 32-byte key from the platform Keychain/Keystore:

```rust
let store = SqliteStore::open_keyed("hop.db", &key)?; // key: &[u8; 32]
```

`open_keyed` needs the `sqlcipher` feature (SQLite + SQLCipher, vendored OpenSSL):

```toml
hop-store-sqlite = { version = "0.0", default-features = false, features = ["sqlcipher"] }
```

`SqliteStore::open_in_memory()` is the ephemeral variant; `opens_as_plaintext` and
`migrate_plaintext_to_keyed` help move an existing plaintext db under encryption.

## Shape

- **Two tables.** `bundles(id, data)` holds the currently-held bundles (postcard-encoded); `seen(id)` is
  the dedup set, retained after a bundle is removed so a re-offered duplicate is still rejected.
- **Flood-bounded dedup.** The `seen` set is clamped in both retained lifetime and row count, so an
  unauthenticated §39 bundle flood can't pin the table open or grow it without bound.
- **Copy budget in the row.** The spray-and-wait copy count lives in the encoded `data` and is
  re-encoded on mutation, so a read always reflects current state.
- **Default is plaintext on disk.** The `bundled` default build stores cleartext; a plaintext build must
  still rely on OS file protection. Build with `sqlcipher` and a real key to encrypt (DESIGN.md §13.2).

## Status

Prototype. The `Store` contract, the copy mutations, the dedup clamps, and both open paths are covered by
the crate's tests (`cargo test -p hop-store-sqlite`, and `--features sqlcipher` for the encrypted path).

## The Hop family

`hop-store-sqlite` is one backend behind [hop-core](https://github.com/hopmesh/hop-core)'s `Store` trait;
[hop-store-firestore](https://crates.io/crates/hop-store-firestore) is the cloud-relay backend. The C ABI
over the core is [libhop](https://github.com/hopmesh/libhop); the browser build is
[hop-wasm](https://github.com/hopmesh/hop-wasm). The language SDKs:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir) ·
[apple](https://github.com/hopmesh/hop-sdk-apple) ·
[android](https://github.com/hopmesh/hop-sdk-android).

## License

[FSL-1.1-ALv2](./LICENSE.md): source-available, and converts to Apache-2.0 after two years. The SDKs
that bind this are Apache-2.0.
