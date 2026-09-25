"""Ed25519 signatures, compatible with libsodium's ``crypto_sign``.

Example::

    from dryoc.sign import SigningKey

    signing_key = SigningKey.generate()
    signature = signing_key.sign(b"message")
    signing_key.verify_key.verify(signature, b"message")  # raises CryptoError if invalid
"""

from __future__ import annotations

from dryoc._dryoc import sign_Ed25519ph as Ed25519ph
from dryoc._dryoc import sign_SigningKey as SigningKey
from dryoc._dryoc import sign_VerifyKey as VerifyKey

__all__ = ["Ed25519ph", "SigningKey", "VerifyKey"]
