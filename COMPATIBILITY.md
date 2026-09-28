# Compatibility with libsodium

dryoc's Classic API (`src/classic/`, `crypto_*`) matches libsodium's wire
formats and function semantics, so supported operations interoperate:
ciphertexts, hashes, signatures, KEM transcripts, and secretstream flows
produced by one verify and decrypt under the other. Constants match
libsodium (`src/constants.rs` asserts equality against libsodium's headers
in the native tests). Native compatibility tests (`#[cfg(dryoc_native_tests)]`
throughout `src/`, via the `libsodium-sys-stable` dev-dependency and the
wrappers in `src/native_test_util.rs`) check dryoc against libsodium 1.0.22.

The exceptions are deliberate, documented at each function, and summarized
here.

## Implemented

Implemented below, libsodium mirrors checked against [1.0.22](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE):

* [Public-key authenticated encryption](https://docs.rs/dryoc/latest/dryoc/dryocbox/index.html) (`crypto_box_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
* [Secret-key authenticated encryption](https://docs.rs/dryoc/latest/dryoc/dryocsecretbox/index.html) (`crypto_secretbox_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secretbox)
* [Curve25519 scalar multiplication](https://docs.rs/dryoc/latest/dryoc/classic/crypto_core/index.html) (`crypto_scalarmult*`) [libsodium link](https://doc.libsodium.org/advanced/scalar_multiplication)
* Zeroing memory (`sodium_memzero`) with [zeroize](https://crates.io/crates/zeroize) [libsodium link](https://doc.libsodium.org/memory_management)
* [Generating random data](https://docs.rs/dryoc/latest/dryoc/rng/index.html) (`randombytes_buf`) [libsodium link](https://doc.libsodium.org/generating_random_data)
* [Encrypted streams](https://docs.rs/dryoc/latest/dryoc/dryocstream/index.html) (`crypto_secretstream_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secretstream)
* [XChaCha20-Poly1305-IETF AEAD](https://docs.rs/dryoc/latest/dryoc/dryocaead/index.html) (`crypto_aead_xchacha20poly1305_ietf_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
* [ChaCha20-Poly1305-IETF AEAD](https://docs.rs/dryoc/latest/dryoc/dryocaead/chacha20poly1305_ietf/index.html) (`crypto_aead_chacha20poly1305_ietf_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction)
* [Memory locking](https://docs.rs/dryoc/latest/dryoc/protected/index.html) (`sodium_mlock`, `sodium_munlock`, `sodium_mprotect_*`) [libsodium link](https://doc.libsodium.org/memory_management)
* [Encrypting related messages](https://docs.rs/dryoc/latest/dryoc/utils/fn.increment_bytes.html) (`sodium_increment`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/encrypted-messages)
* [Generic hashing](https://docs.rs/dryoc/latest/dryoc/generichash/index.html) (`crypto_generichash_*`) [libsodium link](https://doc.libsodium.org/hashing/generic_hashing)
* [Secret-key authentication](https://docs.rs/dryoc/latest/dryoc/auth/index.html) (`crypto_auth*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)
* [One-time authentication](https://docs.rs/dryoc/latest/dryoc/onetimeauth/index.html) (`crypto_onetimeauth_*`) [libsodium link](https://doc.libsodium.org/advanced/poly1305)
* [Sealed boxes](https://docs.rs/dryoc/latest/dryoc/dryocbox/struct.DryocBox.html#method.seal) (`crypto_box_seal*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
* [Key derivation](https://docs.rs/dryoc/latest/dryoc/kdf/index.html) (`crypto_kdf_*`) [libsodium link](https://doc.libsodium.org/key_derivation)
* [Key exchange](https://docs.rs/dryoc/latest/dryoc/kx/index.html) (`crypto_kx_*`) [libsodium link](https://doc.libsodium.org/key_exchange)
* [Post-quantum key encapsulation](https://docs.rs/dryoc/latest/dryoc/kem/index.html) with X-Wing and ML-KEM-768 (`crypto_kem_*`, `crypto_kem_xwing_*`, `crypto_kem_mlkem768_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/key_encapsulation)
* [Post-quantum sealed boxes](https://docs.rs/dryoc/latest/dryoc/dryocsealedbox/index.html): HPKE (RFC 9180) with X-Wing, HKDF-SHA256 and ChaCha20-Poly1305 (dryoc extension) [RFC 9180 link](https://www.rfc-editor.org/rfc/rfc9180.html)
* [Public-key signatures](https://docs.rs/dryoc/latest/dryoc/sign/index.html) (`crypto_sign_*`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [Ed25519 to Curve25519](https://docs.rs/dryoc/latest/dryoc/classic/crypto_sign_ed25519/index.html) (`crypto_sign_ed25519_*`) [libsodium link](https://doc.libsodium.org/advanced/ed25519-curve25519)
* [Signature secret-key extraction helpers](https://docs.rs/dryoc/latest/dryoc/classic/crypto_sign_ed25519/index.html) (`crypto_sign_ed25519_sk_to_seed`, `crypto_sign_ed25519_sk_to_pk`) [libsodium link](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
* [SHA-2 hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_hash/index.html) (`crypto_hash_sha256_*`, `crypto_hash_sha512_*`) [libsodium link](https://doc.libsodium.org/advanced/sha-2_hash_function)
* [SHA-3 hashing](https://docs.rs/dryoc/latest/dryoc/sha3/index.html) (`crypto_hash_sha3256_*`, `crypto_hash_sha3512_*`) [NIST FIPS 202 link](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf)
* [Extendable-output functions](https://docs.rs/dryoc/latest/dryoc/xof/index.html) (`crypto_xof_shake128_*`, `crypto_xof_shake256_*`, `crypto_xof_turboshake128_*`, `crypto_xof_turboshake256_*`) [libsodium link](https://doc.libsodium.org/hashing/xof)
* [Short-input hashing](https://docs.rs/dryoc/latest/dryoc/classic/crypto_shorthash/index.html) (`crypto_shorthash`) [libsodium link](https://doc.libsodium.org/hashing/short-input_hashing)
* [Password hashing](https://docs.rs/dryoc/latest/dryoc/pwhash/index.html) (`crypto_pwhash_*`) [libsodium link](https://doc.libsodium.org/password_hashing/default_phf)
* [HKDF key derivation variants](https://docs.rs/dryoc/latest/dryoc/hkdf/index.html) (`crypto_kdf_hkdf_sha256_*`, `crypto_kdf_hkdf_sha512_*`) [libsodium link](https://doc.libsodium.org/key_derivation/hkdf)
* [Direct HMAC authentication variants](https://docs.rs/dryoc/latest/dryoc/hmac/index.html) (`crypto_auth_hmacsha256_*`, `crypto_auth_hmacsha512_*`, `crypto_auth_hmacsha512256_*`) [libsodium link](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication)

## Deliberate behavior differences

### AEAD decrypt never writes before verifying

`crypto_aead_chacha20poly1305_ietf_*` and
`crypto_aead_xchacha20poly1305_ietf_*` check buffer lengths and verify the
tag before writing anything, so any error leaves the output (or, in place,
`data`) exactly as found. On a failed tag check libsodium zeroes the output
buffer, destroying the ciphertext when decrypting in place; dryoc leaves it
so the caller can retry or preserve it. See "Behavior on failure" in
`src/classic/crypto_aead_chacha20poly1305_ietf.rs` and
`src/classic/crypto_aead_xchacha20poly1305_ietf.rs`.

### XOF enforces the documented rules

`crypto_xof_*`: `init_with_domain` accepts only domain bytes `0x01..=0x7f`
(`Error::InvalidValue` otherwise), and `update` after squeezing has started
fails with `Error::InvalidState` and leaves the state unchanged. libsodium
documents the same rules but does not enforce them: it accepts any domain
byte, and an `update` after squeezing returns `-1` after resetting the state
and absorbing the input anyway. See `src/classic/crypto_xof.rs`.

### dryoc errors where libsodium aborts

`crypto_generichash_final` returns `Error::InvalidLength` when `output` is
empty or longer than 64 bytes; libsodium aborts on those lengths instead.
Within the accepted range, a length different from the `init` length is not
rejected: `output` truncates or extends the chaining value exactly as
libsodium does. See `src/classic/crypto_generichash.rs`.

### Ed25519 validity baseline and deterministic signing

`crypto_core_ed25519_is_valid_point` matches libsodium 1.0.21 and later:
versions through 1.0.20 incorrectly accepted some mixed-order points, which
dryoc rejects. See `src/classic/crypto_core.rs`.

`crypto_sign_*` does not implement libsodium's opt-in
`ED25519_NONDETERMINISTIC` signing mode; signatures are deterministic. See
`src/classic/crypto_sign.rs`.

### Secretstream quirks preserved

`crypto_secretstream_xchacha20poly1305_push`/`pull` replicate libsodium's
padding/alignment quirk
([`290197b`](https://github.com/jedisct1/libsodium/commit/290197ba3ee72245fdab5e971c8de43a82b19874))
so streams interoperate bit-for-bit. `pull` writes the plaintext into the
caller's `message` buffer and returns its length; the caller resizes
afterwards, mirroring libsodium. See
`src/classic/crypto_secretstream_xchacha20poly1305.rs`.

## Not implemented

The following libsodium features are incomplete, internal only, or not
implemented. Other crates may provide equivalent functionality.

* [AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead) beyond the ChaCha20-Poly1305-IETF variants, including AEGIS-128L/256, AES256-GCM, and the legacy 64-bit-nonce ChaCha20-Poly1305 construction
* XChaCha20-Poly1305 box and secretbox variants (`crypto_box_curve25519xchacha20poly1305_*`, `crypto_secretbox_xchacha20poly1305_*`)
* Deterministic random data for reproducible tests (`randombytes_buf_deterministic`)
* Short-input hash variants beyond SipHash-2-4 with 64-bit output (`crypto_shorthash_siphashx24_*`)
* [IP address encryption](https://doc.libsodium.org/secret-key_cryptography/ip_address_encryption) (`crypto_ipcrypt_*`, `sodium_ip2bin`, `sodium_bin2ip`), added in libsodium 1.0.21
* [Helpers](https://doc.libsodium.org/helpers), [padding](https://doc.libsodium.org/padding), and constant-time verify utilities (`sodium_*`, `crypto_verify_*`). dryoc covers the pieces its APIs need: `utils::increment_bytes` (`sodium_increment`), the `protected` module (`sodium_mlock` / `sodium_mprotect_*`), and `zeroize` (`sodium_memzero`)
* Standalone [stream cipher](https://doc.libsodium.org/advanced/stream_ciphers) APIs (`crypto_stream_*`; use the [salsa20](https://crates.io/crates/salsa20) or [chacha20](https://crates.io/crates/chacha20) crates directly instead). dryoc's ChaCha20/Salsa20 code exists only behind the AEAD, box, secretbox, and secretstream APIs
* [Advanced features](https://doc.libsodium.org/advanced):
  * Keccak-f[1600] core permutation (`crypto_core_keccak1600_*`)
  * [Scrypt](https://doc.libsodium.org/advanced/scrypt) (`crypto_pwhash_scryptsalsa208sha256_*`; use the [scrypt](https://crates.io/crates/scrypt) crate directly instead). dryoc implements Argon2i and Argon2id only
  * [Finite field and group arithmetic](https://doc.libsodium.org/advanced/point-arithmetic) (`crypto_core_ed25519_*`, `crypto_core_ristretto255_*`; try the [curve25519-dalek](https://crates.io/crates/curve25519-dalek) crate). dryoc exposes `crypto_core_ed25519_is_valid_point`, `crypto_core_hchacha20`, `crypto_core_hsalsa20`, and `crypto_scalarmult` / `crypto_scalarmult_base`
  * Ed25519 and Ristretto255 scalar multiplication variants (`crypto_scalarmult_ed25519_*`, `crypto_scalarmult_ristretto255_*`)

## dryoc extensions

These have no libsodium equivalent and use dryoc-defined formats.

* Post-quantum sealed boxes: HPKE (RFC 9180) with X-Wing, HKDF-SHA256, and
  ChaCha20-Poly1305 (`src/dryocsealedbox.rs`).
* AEAD envelopes: `DryocAeadEnvelope` / `VecEnvelope` store
  `nonce || ciphertext || tag` with a freshly generated nonce (`seal` /
  `open`); libsodium interop is at the `ciphertext || tag` box level
  (`src/dryocaead.rs`). The Python `aead` envelope and post-quantum
  `sealedbox` likewise use these dryoc formats (see
  [python/README.md](python/README.md#compatibility)).
* The typed Rustaceous API, protected memory, `#![no_std]` / `alloc`
  gating, and Serde / wincode support.
* API shape beyond libsodium's C signatures with identical wire bytes:
  `*_inplace` encrypt/decrypt variants and `*_keygen_inplace` /
  `*_seed_keypair_inplace` constructors.
* `CRYPTO_KEM_MLKEM768_ENCSEEDBYTES` and `CRYPTO_KEM_XWING_ENCSEEDBYTES`:
  the seed lengths for the deterministic KEM test-encapsulation functions.
  libsodium exposes the functions but no named constant for them
  (`src/constants.rs`).
