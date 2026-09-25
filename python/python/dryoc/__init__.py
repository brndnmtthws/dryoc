"""dryoc: Don't Roll Your Own Crypto.

Pythonic bindings to `dryoc <https://github.com/brndnmtthws/dryoc>`_, a
pure-Rust cryptography library that is wire-compatible with libsodium.

Modules:

* :mod:`dryoc.secretbox` -- secret-key authenticated encryption
* :mod:`dryoc.aead` -- ChaCha20-Poly1305 AEADs with associated data
* :mod:`dryoc.box` -- public-key authenticated and anonymous (sealed) boxes
* :mod:`dryoc.sealedbox` -- post-quantum sealed boxes (HPKE with X-Wing)
* :mod:`dryoc.secretstream` -- encrypted message streams
* :mod:`dryoc.sign` -- Ed25519 signatures
* :mod:`dryoc.kx` -- X25519 session-key exchange
* :mod:`dryoc.kem` -- post-quantum key encapsulation (X-Wing, ML-KEM-768)
* :mod:`dryoc.hash` -- SHA-2, SHA-3, BLAKE2b and SHAKE with the hashlib API
* :mod:`dryoc.mac` -- HMAC-SHA-2 and Poly1305
* :mod:`dryoc.kdf` -- BLAKE2b subkey derivation and HKDF
* :mod:`dryoc.pwhash` -- Argon2 password hashing
"""

from dryoc import (
    aead,
    box,
    exceptions,
    hash,
    kdf,
    kem,
    kx,
    mac,
    pwhash,
    sealedbox,
    secretbox,
    secretstream,
    sign,
)
from dryoc._dryoc import __version__, random_bytes
from dryoc._types import EncryptedMessage
from dryoc.kx import SessionKeys
from dryoc.exceptions import CryptoError, DryocError, InvalidInputError

__all__ = [
    "CryptoError",
    "DryocError",
    "EncryptedMessage",
    "InvalidInputError",
    "SessionKeys",
    "__version__",
    "aead",
    "box",
    "exceptions",
    "hash",
    "kdf",
    "kem",
    "kx",
    "mac",
    "pwhash",
    "random_bytes",
    "sealedbox",
    "secretbox",
    "secretstream",
    "sign",
]
