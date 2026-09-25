"""Secret-key authenticated encryption: XSalsa20-Poly1305, compatible with
libsodium's ``crypto_secretbox``.

Example::

    from dryoc.secretbox import SecretBox

    key = SecretBox.generate()
    message = key.encrypt(b"attack at dawn")
    assert key.decrypt(*message) == b"attack at dawn"
"""

from __future__ import annotations

from dryoc._dryoc import secretbox_SecretBox as SecretBox
from dryoc._types import EncryptedMessage

__all__ = ["EncryptedMessage", "SecretBox"]
