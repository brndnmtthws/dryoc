# dryoc for Python

**Don't Roll Your Own Crypto**: Pythonic bindings to
[dryoc](https://github.com/brndnmtthws/dryoc), a pure-Rust cryptography
library that is wire-compatible with [libsodium](https://doc.libsodium.org/).

- Authenticated encryption, public-key boxes, sealed boxes, encrypted
  streams, Ed25519 signatures, key exchange, Argon2 password hashing,
  BLAKE2b/SHA-2/SHA-3/SHAKE hashing, HMAC, HKDF, and post-quantum key
  encapsulation (ML-KEM-768 and X-Wing).
- Output interoperates with libsodium (and so with PyNaCl, libsodium.js,
  and friends) wherever libsodium defines the format.
- No C dependencies: libsodium is not needed at build or run time.
- Typed (`py.typed` and complete stubs), with errors you cannot ignore by
  accident.

## Installation

```sh
pip install dryoc
```

Prebuilt wheels are published for Linux x86_64 and aarch64 (manylinux),
macOS arm64 and Windows x86_64: one `abi3` wheel per platform for CPython
3.10 and newer, plus a separate wheel for free-threaded CPython 3.14t. On
other platforms (musl/Alpine, Intel macOS, Windows on ARM, PyPy) pip builds
from the source distribution, which needs a Rust toolchain, version 1.89 or
newer.

## Quick tour

### Secret-key encryption

```python
from dryoc.secretbox import SecretBox

key = SecretBox.generate()                 # or SecretBox(existing_32_byte_key)
message = key.encrypt(b"attack at dawn")   # a random nonce is generated
ciphertext, nonce = message                # EncryptedMessage(ciphertext, nonce)
assert key.decrypt(ciphertext, nonce) == b"attack at dawn"
assert key.decrypt(*message) == b"attack at dawn"
```

### Authenticated encryption with associated data

```python
from dryoc.aead import XChaCha20Poly1305

key = XChaCha20Poly1305.generate()

# `seal` generates a nonce and returns one self-contained blob:
# nonce || ciphertext || tag.
envelope = key.seal(b"card number", associated_data=b"user 42")
assert key.open(envelope, associated_data=b"user 42") == b"card number"

# Or manage nonces yourself, in libsodium's ciphertext || tag format.
message = key.encrypt(b"card number", associated_data=b"user 42")
assert key.decrypt(*message, associated_data=b"user 42") == b"card number"
```

`dryoc.aead.ChaCha20Poly1305` (RFC 8439) is also available; its 96-bit
nonces are too short to pick at random, so it always takes an explicit nonce.

### Public-key encryption

```python
from dryoc.box import Box, KeyPair, SealedBox

alice, bob = KeyPair.generate(), KeyPair.generate()

# Authenticated: Bob knows the message came from Alice.
message = Box(alice, bob.public_key).encrypt(b"hi Bob")
assert Box(bob, alice.public_key).decrypt(*message) == b"hi Bob"

# Anonymous: anyone can encrypt to Bob; only Bob can decrypt.
sealed = SealedBox(bob.public_key).encrypt(b"a secret admirer")
assert SealedBox(bob).decrypt(sealed) == b"a secret admirer"
```

### Post-quantum sealed boxes and key encapsulation

```python
from dryoc.kem import xwing
from dryoc.sealedbox import SealedBox

recipient = xwing.KeyPair.generate()    # X-Wing: ML-KEM-768 + X25519

sealed = SealedBox(recipient.public_key).encrypt(b"store now, decrypt never")
assert SealedBox(recipient).decrypt(sealed) == b"store now, decrypt never"

ciphertext, shared_secret = recipient.public_key.encapsulate()
assert recipient.decapsulate(ciphertext) == shared_secret
```

`dryoc.kem.mlkem768` offers ML-KEM-768 (FIPS 203) alone for protocols that
require it.

### Encrypted streams

```python
from dryoc.secretstream import Decryptor, Encryptor, Key, Tag

key = Key.generate()
with Encryptor(key) as encryptor:
    header = encryptor.header
    chunks = [
        encryptor.push(b"first chunk"),
        encryptor.push(b"last chunk", tag=Tag.FINAL),
    ]

received = []
with Decryptor(key, header) as decryptor:
    for chunk in chunks:
        message, tag = decryptor.pull(chunk)
        received.append(message)
assert received == [b"first chunk", b"last chunk"]
```

Reordered, duplicated, dropped or modified chunks raise `CryptoError`. Used
as context managers, both sides wipe their state on exit, and they raise if
the block ends before the `Tag.FINAL` message, so a truncated stream is never
mistaken for a complete one.

### Signatures

```python
from dryoc import CryptoError
from dryoc.sign import SigningKey

signing_key = SigningKey.generate()
signature = signing_key.sign(b"release v2.0.0")

verify_key = signing_key.verify_key          # share bytes(verify_key)
verify_key.verify(signature, b"release v2.0.0")  # returns None, or raises
try:
    verify_key.verify(signature, b"release v6.6.6")
except CryptoError:
    print("forgery detected")
```

`dryoc.sign.Ed25519ph` signs messages too large to hold in memory,
incrementally.

### Password hashing

```python
from dryoc import CryptoError, pwhash, random_bytes

stored = pwhash.hash("correct horse battery staple")   # "$argon2id$v=19$..."
pwhash.verify(stored, "correct horse battery staple")  # raises CryptoError if wrong

salt = random_bytes(pwhash.SALT_SIZE)
key = pwhash.derive_key("passphrase", salt, strength=pwhash.Strength.MODERATE)
assert len(key) == 32
```

Presets are `Strength.INTERACTIVE` (the default), `MODERATE` and
`SENSITIVE`, as in libsodium; `opslimit` and `memlimit` override them.
Hashing runs with the GIL released.

### Key exchange

```python
from dryoc import kx
from dryoc.secretbox import SecretBox

client, server = kx.KeyPair.generate(), kx.KeyPair.generate()
client_keys = kx.client_session_keys(client, server.public_key)
server_keys = kx.server_session_keys(server, client.public_key)

message = SecretBox(client_keys.tx).encrypt(b"hello server")
assert SecretBox(server_keys.rx).decrypt(*message) == b"hello server"
```

### Hashing

The hashers follow the `hashlib` interface; the lowercase functions are
one-shot.

```python
from dryoc import hash

assert hash.sha256(b"abc") == hash.Sha256(b"abc").digest()

h = hash.Blake2b(digest_size=32, key=b"k" * 32)   # keyed BLAKE2b
h.update(b"streamed ")
h.update(b"input")
tag = h.hexdigest()

xof = hash.TurboShake128(b"seed material")
reader = xof.reader()
first, second = reader.read(32), reader.read(32)
```

`Blake2b` follows libsodium's `crypto_generichash`, so its default digest is
32 bytes (`hashlib.blake2b` defaults to 64). Also available: `Sha512`,
`Sha3_256`, `Sha3_512`, `Shake128`, `Shake256` and `TurboShake256`.

### MACs and key derivation

```python
from dryoc import kdf, mac

key = mac.HmacSha512256.generate_key()
tag = mac.hmac_sha512256(key, b"message")
mac.HmacSha512256(key, b"message").verify(tag)    # constant time; raises on mismatch

master = kdf.Kdf.generate(context=b"MyApp v1")   # libsodium crypto_kdf
encryption_key, signing_seed = master.derive(1), master.derive(2)

okm = kdf.hkdf_sha256(b"input keying material", salt=b"salt", info=b"purpose")
```

`mac` also provides `HmacSha256`, `HmacSha512` and the one-time
authenticator `Poly1305`.

## Conventions

- **Keys are objects.** Create them with `generate()`, from raw bytes with
  `Cls(data)` / `Cls.from_bytes(data)`, or (for key pairs) `from_seed()` and
  `from_secret_key()`. Wrong lengths raise `InvalidInputError`, which is a
  `ValueError`.
- **Secrets stay secret.** Secret keys have a redacted `repr`, compare in
  constant time, are unhashable and unpicklable, and are wiped from memory
  when garbage-collected. Export them deliberately with `bytes(key)`.
- **Failures raise.** Every dryoc exception derives from
  `dryoc.DryocError`. Authentication, decryption and verification failures
  raise `dryoc.CryptoError`; nothing returns `None` or `False` to signal a
  forgery.
- **Any bytes-like input.** `bytes`, `bytearray`, `memoryview`, `array`,
  NumPy arrays and other buffer-protocol objects are accepted; results are
  `bytes`. Mutable buffers are copied (and the copy wiped) before use, so
  another thread cannot change them mid-operation.
- **Threads.** Password hashing and operations on inputs of 2 KiB or more run
  with the GIL released. Key objects are immutable; stateful objects
  (hashers, MACs, streams) serialize concurrent calls. The extension declares
  support for free-threaded CPython.

## Compatibility

Formats match libsodium: `crypto_secretbox_easy`, `crypto_box_easy`,
`crypto_box_seal`, `crypto_aead_*chacha20poly1305_ietf`,
`crypto_secretstream_xchacha20poly1305`, `crypto_sign` (combined and
detached), `crypto_kx`, `crypto_kdf`, `crypto_generichash`, `crypto_pwhash_str`
and `crypto_kem_xwing`. The `aead` envelope (`seal`/`open`) and the
post-quantum `sealedbox` use the formats of dryoc's Rust API; see the
[dryoc documentation](https://docs.rs/dryoc).

## Security

dryoc has not undergone a third-party security audit. Follow the documented
nonce and key rules, and see the
[project repository](https://github.com/brndnmtthws/dryoc) for details.

## License

MIT
