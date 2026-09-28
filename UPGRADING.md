# Upgrading from dryoc 1.x to 2.0

dryoc 2.0 removes deprecated names, makes the Rust API more consistent, and
adds `no_std` support. The wire formats did not change: data that 1.x wrote
(boxes, AEAD envelopes, signed messages, secret streams, password hash
strings, and serde and wincode encodings) reads the same in 2.0, and 2.0
writes the same bytes. The minimum supported Rust version is still 1.89.

Nearly every change below causes a compile error, so the fastest way to
upgrade is to bump the version, build, and use this page to look up each
error. The changes that do not cause a compile error are listed in
[Changes that still compile](#changes-that-still-compile).

## Cargo features

```toml
# 1.x
dryoc = { version = "1", features = ["serde", "wincode"] }
# 2.0 (serde is now a default feature)
dryoc = { version = "2", features = ["wincode_0_6"] }
```

- `serde` is now enabled by default. You can remove it from `features`.
- `wincode` is renamed `wincode_0_6`. The name includes the wincode version
  because wincode's traits are part of dryoc's API. A later wincode release
  will get its own feature next to this one. Your crate must also move to
  wincode 0.6 (dryoc 1.0 used 0.5). The encoded bytes are the same.
- `u64_backend` is removed. It did nothing. Delete it from `features`, or
  Cargo will fail to resolve the dependency.
- The crate is now `#![no_std]`, with new `std` and `alloc` features. `std`
  is a default feature and enables `alloc`. If you set
  `default-features = false`, you now get a `no_std` build without
  allocation. To keep what 1.x gave you, add `std`, or `alloc` on targets
  without `std`:

  ```toml
  dryoc = { version = "2", default-features = false, features = ["std"] }
  ```

  - Without `alloc`, APIs that return `Vec` or `String` are unavailable:
    `Vec*` types, `*_to_vec`, `*_to_vecbox`, `rng::randombytes_buf`,
    `pwhash` and `classic::crypto_pwhash`.
  - `Error::Io` and `From<std::io::Error> for Error` need `std`.
  - `protected` now enables `std`. `base64` and `wincode_0_6` enable `alloc`.
  - Without `std`, CPU-specific kernels are selected at compile time from the
    target features (for example `-C target-cpu=native`) instead of being
    detected at runtime.
  - Bare-metal targets need a custom `getrandom` backend. See the `rng`
    module docs.
- `nightly` no longer enables `protected`. If you use
  `default-features = false` with `nightly` and need protected memory, add
  `protected`. The `nightly` feature needs `nightly-2026-09-24` or later.

## Generating keys and constructing values

The `gen` names were deprecated in 1.x and are now removed: Rust 2024
reserves `gen` as a keyword. The `*_with_defaults` methods are replaced by
type aliases that fix the default types.

| 1.x | 2.0 |
|---|---|
| `Key::r#gen()` and other `NewByteArray::r#gen()` | `Key::generate()` |
| `x.gen_locked()` / `gen_readonly_locked()` | `generate_locked()` / `generate_readonly_locked()` |
| `KeyPair::gen_locked_keypair()` / `gen_readonly_locked_keypair()` (also `SigningKeyPair`) | `generate_locked_keypair()` / `generate_readonly_locked_keypair()` |
| `KeyPair::gen()`, `KeyPair::gen_with_defaults()`, `KeyPair::generate_with_defaults()` | `keypair::StackKeyPair::generate()` (also `dryocbox::StackKeyPair`, `kx::StackKeyPair`) |
| `SigningKeyPair::gen_with_defaults()` / `generate_with_defaults()` | `sign::StackSigningKeyPair::generate()` |
| `Kdf::gen_with_defaults()` / `generate_with_defaults()` | `kdf::StackKdf::generate()` |
| `Hkdf::gen_with_defaults()` / `generate_with_defaults()` | `hkdf::HkdfSha256::generate()` or `HkdfSha512::generate()` |
| `KeyPair::new()`, `KeyPair::default()`, `KeyPair::new_locked_keypair()` (also `SigningKeyPair`) | removed; see below |
| `StackByteArray::<N>::new()`, `Key::new()`, `Nonce::new()`, ... | `::default()`, or `NewByteArray::new_byte_array()` in generic code |

`KeyPair::new()`, `SigningKeyPair::new()`, their `Default` impls and
`new_locked_keypair()` returned an all-zero secret key. They are removed. To
make a key pair, use `generate()`, `from_seed()`, `from_secret_key()`, or one
of the `generate_*locked_keypair()` constructors. If you really need an
all-zero placeholder, build it from the public fields:

```rust
use dryoc::keypair::{PublicKey, SecretKey, StackKeyPair};

let placeholder = StackKeyPair {
    public_key: PublicKey::default(),
    secret_key: SecretKey::default(),
};
```

## Fixed-size inputs must have the right type

In 1.x, `ByteArray<N>` and `MutByteArray<N>` were implemented for `&[u8]`,
`[u8]` and `Vec<u8>`. Passing a slice or `Vec` as a key, nonce, public key,
tag or signature compiled. A short input panicked, and a long one was
silently cut to length. In 2.0 these impls, and `NewByteArray` for `Vec<u8>`,
are removed. Convert runtime-length bytes yourself and handle the length
error:

```rust
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};

let key = Key::try_from(key_bytes.as_slice())?; // Error::InvalidLength if the length is wrong
let nonce = Nonce::try_from(nonce_bytes.as_slice())?;
let sealed = DryocSecretBox::encrypt_to_vecbox(message, &nonce, &key)?;
```

- A MAC or signature received as bytes needs the same conversion, for example
  `Mac::try_from(bytes)?`.
- A generic output like `let mac: Vec<u8> = Auth::compute(..)` needs a
  fixed-size type (`Mac`, `StackByteArray<N>`, `[u8; N]`) or the matching
  `*_to_vec` method.
- Box types with `Vec` tags or keys, such as `DryocBox<Vec<u8>, Vec<u8>, _>`,
  need fixed-size field types. To read a box from bytes, use
  `VecBox::from_bytes`.

## Imports and paths

The algorithm modules no longer re-export everything from `dryoc::types`. If
you imported `use dryoc::dryocbox::*;` and then called trait methods such as
`Nonce::generate()` or `.as_slice()`, also import the traits:

```rust
use dryoc::dryocbox::*;
use dryoc::types::*;
```

This applies to `dryocaead`, `dryocbox`, `dryocsecretbox`, `dryocstream` and
`generichash`. `X::protected::*` globs still include the traits.

| 1.x | 2.0 |
|---|---|
| `dryoc::dryocbox::NewByteArray` (any `types` item through an algorithm module) | `dryoc::types::NewByteArray` |
| `dryoc::keypair::protected::*`, `dryoc::precalc::protected::*` | `dryoc::protected::*` |
| `dryoc::protected::ptypes::Locked` (and the other `ptypes` items) | `dryoc::protected::Locked` |
| `dryocbox::KeyPair` | `dryocbox::StackKeyPair` |
| `kx::KeyPair` | `kx::StackKeyPair` |
| `dryocstream::Nonce`, `dryocstream::protected::Nonce` | removed; no stream API takes a nonce |
| `sha3::Sha3256Digest` / `sha3::Sha3512Digest` | `sha3::Digest256` / `sha3::Digest512` |
| `sign::IncrementalSigner` | `sign::Ed25519phSigner` |
| `utils::sodium_increment(&mut b)` | `utils::increment_bytes(&mut b)` |
| `protected::traits::ReadOnly {}` (and the other marker structs) | `protected::traits::ReadOnly` (unit structs) |

## Boxes

| 1.x | 2.0 |
|---|---|
| `DryocSecretBox::encrypt(..)` returns `Self` | returns `Result<Self, Error>`; add `?` |
| `DryocSecretBox::encrypt_to_vecbox(..)` returns `VecBox` | returns `Result<VecBox, Error>`; add `?` |
| `DryocBox::unseal(&kp)` / `unseal_to_vec(&kp)` | `DryocBox::open(&kp)` / `open_to_vec(&kp)` |
| `AeadEnvelope::seal_to_vec(..)` (`DryocAeadEnvelope`, `VecEnvelope`) | `AeadEnvelope::seal_to_vecbox(..)` |
| `DryocBox::from_parts(tag, data, epk)` | `DryocBox::from_parts(epk, tag, data)` |
| `let (tag, data, epk) = dryocbox.into_parts()` | `let (epk, tag, data) = dryocbox.into_parts()` |
| `DryocBox::new_with_data_and_mac(tag, &data)` | `VecBox::from_parts(None, tag, data.to_vec())` |
| `DryocBox::new_with_epk_data_and_mac(epk, tag, &data)` | `VecBox::from_parts(Some(epk), tag, data.to_vec())` |
| `DryocSecretBox::with_data_and_mac(tag, &data)` | `DryocSecretBox::from_parts(tag, data.to_vec())` |
| `DryocSecretBox::with_data(&data)` (all-zero tag) | `DryocSecretBox::from_parts(tag, data)` with the real tag, or `from_bytes` |
| `AeadBox::with_data_and_mac(tag, &data)` | `AeadBox::from_parts(tag, data.to_vec())` |
| `AeadEnvelope::with_nonce_data_and_mac(nonce, tag, &data)` | `AeadEnvelope::from_parts(nonce, tag, data.to_vec())` |

`DryocBox`'s parts are now in wire order, like the other box types. The box
types and `SignedMessage` also gained borrowing accessors (`tag()`, `data()`,
`ephemeral_pk()`, `signature()`, `message()`).

## Signing

| 1.x | 2.0 |
|---|---|
| `keypair.sign(m)?` | `keypair.sign(m)`; it returns `SignedMessage` and cannot fail |
| `keypair.sign_with_defaults(m)?` | `keypair.sign_to_vecbox(&m)`, which returns `VecSignedMessage` |
| `signer.finalize(&sk)?` (`IncrementalSigner`) | `signer.finalize(&sk)` (`Ed25519phSigner`); it returns the signature |
| `KeyPair::is_valid_ed25519_key(&pk)` | `sign::is_valid_public_key(&pk)` |

`Ed25519phSigner` computes Ed25519ph (prehashed) signatures, like libsodium's
`crypto_sign_init`/`update`/`final_create`. They do not verify as plain
Ed25519 signatures. The type did the same in 1.x; only the name changed.

## Authentication and MACs

`Hmac`, `Auth` and `OnetimeAuth` borrow the key in `compute`,
`compute_to_vec`, `compute_and_verify` and `new`:

| 1.x | 2.0 |
|---|---|
| `HmacSha256::compute(key.clone(), m)` / `HmacSha256::new(key)` | `HmacSha256::compute(&key, m)` / `HmacSha256::new(&key)` |
| `Auth::compute(key.clone(), m)` / `Auth::new(key)` | `Auth::compute(&key, m)` / `Auth::new(&key)` |
| `OnetimeAuth::compute(key, m)` / `OnetimeAuth::new(key)` | `OnetimeAuth::compute(&key, m)` / `OnetimeAuth::new(&key)` |

## Secret streams

| 1.x | 2.0 |
|---|---|
| `stream.push_to_vec(&msg, Some(&ad), tag)` (`ad` of the message's type) | `stream.push_to_vec(&msg, Some(ad), tag)` with `ad: &[u8]`; `Some(&vec)` still works (also `push`, `pull`, `pull_to_vec`) |
| `pull::<_, Out>` with `Out: MutBytes + Default + ResizableBytes` | `pull::<Out, _>` with `Out: NewBytes + ResizableBytes`, like `push` |
| `Tag::MESSAGE` / `PUSH` / `REKEY` / `FINAL` | `Tag::Message` / `Push` / `Rekey` / `Final` |
| `Tag::from_bits(b)` returns `Option<Tag>` | `Tag::try_from(b)` returns `Result<Tag, Error>`; use `.ok()` for an `Option` |
| `Tag::from_bits_retain` / `from_bits_truncate` / `from_name` | removed; use `Tag::try_from` |
| `Tag::empty()` / `Tag::all()` | `Tag::Message` / `Tag::Final`; `Tag::default()` is still `Message` |
| `tag.contains(Tag::REKEY)` | `matches!(tag, Tag::Rekey \| Tag::Final)` |
| bit operators, set methods, `iter`, `iter_names`, `TagIter`, `TagIterNames` | removed; a tag is one value |
| `format!("{tag:x}")` (also `:b`, `:o`, `:X`) | `format!("{:x}", tag.bits())` |

`Tag` is now a `#[non_exhaustive]` enum, so a `match` on it needs a wildcard
arm.

## Key exchange and key pairs

| 1.x | 2.0 |
|---|---|
| `KeyPair::is_valid_public_key(&pk)` | `keypair::is_valid_public_key(&pk)` |
| `keypair.kx_new_client_session(&server_pk)` | `kx::StackSession::new_client(&keypair, &server_pk)` |
| `keypair.kx_new_server_session(&client_pk)` | `kx::StackSession::new_server(&keypair, &client_pk)` |
| `Session::new_client_with_defaults(..)` / `new_server_with_defaults(..)` | `StackSession::new_client(..)` / `StackSession::new_server(..)` |

`KeyPair::precalculate` now accepts any `ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>`
as the other party's public key.

## KDF, HKDF, hashing and password hashing

| 1.x | 2.0 |
|---|---|
| `HkdfSha256::extract(None::<&[u8]>, ikm)` | `HkdfSha256::extract(None, ikm)`; the salt is `Option<&[u8]>` |
| `HkdfSha256::extract(Some(&salt), ikm)` with a non-slice salt | `HkdfSha256::extract(Some(salt.as_slice()), ikm)` |
| `hkdf.expand_to_vec(len, context)` / `expand_to_bytes(len, context)` | `hkdf.expand_to_vec(context, len)` / `expand_to_bytes(context, len)` |
| `Hkdf::extract_and_expand_to_vec(len, salt, ikm, ctx)` (also `_to_bytes`) | `Hkdf::extract_and_expand_to_vec(salt, ikm, ctx, len)` |
| `HkdfVariant::Prk` | removed; name the PRK type (`HkdfSha256Prk`, `StackByteArray<N>`, ...) |
| `GenericHash::new_with_defaults(key)` | `generichash::DefaultGenericHash::new(key)` |
| `GenericHash::hash_with_defaults(i, key)` / `hash_with_defaults_to_vec(i, key)` | `DefaultGenericHash::hash(i, key)` / `DefaultGenericHash::hash_to_vec(i, key)` |
| `PwHash::hash_with_defaults(pw)` | `VecPwHash::hash(pw, Config::interactive())` |
| `PwHash::hash_interactive(pw)` / `hash_moderate(pw)` / `hash_sensitive(pw)` | `PwHash::hash(pw, Config::interactive())` / `Config::moderate()` / `Config::sensitive()` |
| `PwHash::from_string_with_defaults(s)` | `VecPwHash::from_string(s)` |

## Generic parameter order

This only matters if you name generic parameters with a turbofish (`::<..>`).
The type you choose for the output now comes first, followed by the other
types in argument order. Const lengths stay first. Examples:

| 1.x | 2.0 |
|---|---|
| `Auth::compute::<_, _, Mac>(..)` (also `OnetimeAuth`, `Hmac`) | `Auth::compute::<Mac, _, _>(..)` |
| `Sha256::compute::<_, Out>(..)` (also `Sha512`, `Sha3256`, `Sha3512`, `compute_into_bytes`) | `Sha256::compute::<Out, _>(..)` |
| `GenericHash::hash::<_, Key, Out>(..)` | `GenericHash::hash::<Out, _, Key>(..)` |
| `DryocBox::decrypt::<N, PK, SK, Out>(..)` | `DryocBox::decrypt::<Out, N, PK, SK>(..)` |
| `DryocBox::precalc_encrypt::<P, M, N>(..)` / `precalc_decrypt::<P, N, Out>(..)` | `precalc_encrypt::<M, N, P>(..)` / `precalc_decrypt::<Out, N, P>(..)` |
| `dryocbox.open::<_, _, Out>(&kp)` | `dryocbox.open::<Out, _, _>(&kp)` |
| `DryocStream::init_push::<K, H>(..)` | `DryocStream::init_push::<H, K>(..)` |
| `stream.push::<_, Out>(..)` / `stream.pull::<_, Out>(..)` | `stream.push::<Out, _>(..)` / `stream.pull::<Out, _>(..)` |
| `hkdf.expand::<N, _, Out>(ctx)` / `extract_and_expand::<N, _, _, _, Out>(..)` | `hkdf.expand::<N, Out, _>(ctx)` / `extract_and_expand::<N, Out, _, _>(..)` |
| `PwHash::derive_keypair::<_, PK, SK>(..)` | `PwHash::derive_keypair::<PK, SK, _>(..)` |

The `*_to_vec` and `*_to_vecbox` methods now fix only the output container and
accept generic inputs. Calls without a turbofish still compile.

## Traits you can no longer implement

These traits are now sealed: `hmac::HmacVariant`, `hkdf::HkdfVariant`,
`dryocstream::Mode`, `protected::traits::ProtectMode` and
`protected::traits::LockMode`. Code that uses them as bounds still compiles.
Their items (`HmacVariant::compute`, `HkdfVariant::OUTPUT_BYTES_MAX`,
`HmacVariant::State`, ...) are no longer public; use the `Hmac` and `Hkdf`
methods.

`NewByteArray::generate()` is now a required method. If you implement
`NewByteArray` for your own type, implement `generate()` instead of `r#gen()`.

## Classic API

`crypto_secretbox_open_detached`, `crypto_box_open_detached` and
`crypto_box_open_detached_afternm` now take the ciphertext before the MAC,
like libsodium and dryoc's own `*_decrypt_detached` AEAD functions:

| 1.x | 2.0 |
|---|---|
| `crypto_secretbox_open_detached(&mut m, &mac, &c, &nonce, &key)` | `crypto_secretbox_open_detached(&mut m, &c, &mac, &nonce, &key)` |
| `crypto_box_open_detached(&mut m, &mac, &c, &nonce, &pk, &sk)` | `crypto_box_open_detached(&mut m, &c, &mac, &nonce, &pk, &sk)` |
| `crypto_box_open_detached_afternm(&mut m, &mac, &c, &nonce, &key)` | `crypto_box_open_detached_afternm(&mut m, &c, &mac, &nonce, &key)` |

The in-place variants and the encryption functions are unchanged. The other
Classic signatures and constants are also unchanged; `crypto_pwhash` needs the
`alloc` feature.

## Changes that still compile

Check these by hand; the compiler will not point them out:

- **Detached open with a 16-byte ciphertext.** The MAC is `&[u8; 16]` and the
  ciphertext `&[u8]`, so an old-order call only compiles if the ciphertext is
  itself a `[u8; 16]`. Such a call now fails authentication at runtime.
- **`crypto_generichash` and `GenericHash` accept libsodium's full ranges.**
  Output lengths from 1 to 64 bytes and keys from 0 to 64 bytes are accepted.
  1.x rejected anything below the recommended 16-byte minimums, including an
  empty key (`Some(&[])`), which now means no key, as in libsodium.
- **Deserializing protected memory.** `HeapBytes` and `LockedBytes` return a
  deserialization error when allocation or locking fails, instead of
  panicking.
- **`#[must_use]`.** Constructors, generators, validity checks, digests and
  MACs are now `#[must_use]`. Ignoring their results triggers the
  `unused_must_use` warning, which is an error under `-D warnings`.
- **CPU feature detection without `std`.** See [Cargo features](#cargo-features).
