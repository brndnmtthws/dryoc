"""Public-key authenticated encryption (X25519-XSalsa20-Poly1305), compatible
with libsodium's ``crypto_box`` and ``crypto_box_seal``.

Example::

    from dryoc.box import Box, KeyPair, SealedBox

    alice, bob = KeyPair.generate(), KeyPair.generate()
    message = Box(alice, bob.public_key).encrypt(b"hi Bob")
    assert Box(bob, alice.public_key).decrypt(*message) == b"hi Bob"

    sealed = SealedBox(bob.public_key).encrypt(b"anonymous")
    assert SealedBox(bob).decrypt(sealed) == b"anonymous"
"""

from __future__ import annotations

from dryoc._dryoc import box_Box as Box
from dryoc._dryoc import box_KeyPair as KeyPair
from dryoc._dryoc import box_PublicKey as PublicKey
from dryoc._dryoc import box_SealedBox as SealedBox
from dryoc._dryoc import box_SecretKey as SecretKey
from dryoc._types import EncryptedMessage

__all__ = ["Box", "EncryptedMessage", "KeyPair", "PublicKey", "SealedBox", "SecretKey"]
