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

These libsodium APIs have no dryoc equivalent. Other crates may provide
them.

* Other `crypto_aead_*` constructions: AEGIS-128L/256, AES256-GCM, and the
  original 64-bit-nonce ChaCha20-Poly1305. dryoc implements only the
  ChaCha20-Poly1305-IETF and XChaCha20-Poly1305-IETF variants.
* XChaCha20-Poly1305 box and secretbox variants
  (`crypto_box_curve25519xchacha20poly1305_*`,
  `crypto_secretbox_xchacha20poly1305_*`).
* Raw stream ciphers (`crypto_stream_chacha20*`,
  `crypto_stream_salsa20*`, `crypto_stream_xchacha20*`); the ChaCha20/Salsa20
  code exists only behind the AEAD, box, secretbox, and secretstream APIs.
* Deterministic randomness for reproducible tests
  (`randombytes_buf_deterministic`).
* Short-input hash variants beyond SipHash-2-4 with 64-bit output
  (`crypto_shorthash_siphashx24_*`).
* IP address encryption (`crypto_ipcrypt_*`), added in libsodium 1.0.21.
* `crypto_verify_*` and most `sodium_*` helpers, padding, and encoding
  utilities. dryoc covers the pieces its APIs need: `utils::increment_bytes`
  (`sodium_increment`), the `protected` module (`sodium_mlock` /
  `sodium_mprotect_*`), and `zeroize` (`sodium_memzero`).
* Scrypt password hashing
  (`crypto_pwhash_scryptsalsa208sha256_*`); dryoc implements Argon2i and
  Argon2id only.
* Ristretto255 group operations and the remaining `crypto_core_ed25519_*` /
  `crypto_scalarmult_ed25519_*` group ops. dryoc exposes
  `crypto_core_ed25519_is_valid_point`, `crypto_core_hchacha20`,
  `crypto_core_hsalsa20`, and `crypto_scalarmult` / `crypto_scalarmult_base`.

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
