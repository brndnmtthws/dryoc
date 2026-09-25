"""Authenticated encryption with associated data: XChaCha20-Poly1305 and
ChaCha20-Poly1305 (RFC 8439), compatible with libsodium's
``crypto_aead_*chacha20poly1305_ietf``.

Example::

    from dryoc.aead import XChaCha20Poly1305

    key = XChaCha20Poly1305.generate()
    envelope = key.seal(b"secret", associated_data=b"header")
    assert key.open(envelope, associated_data=b"header") == b"secret"
"""

from __future__ import annotations

from dryoc._dryoc import aead_ChaCha20Poly1305 as ChaCha20Poly1305
from dryoc._dryoc import aead_XChaCha20Poly1305 as XChaCha20Poly1305
from dryoc._types import EncryptedMessage

__all__ = ["ChaCha20Poly1305", "EncryptedMessage", "XChaCha20Poly1305"]
