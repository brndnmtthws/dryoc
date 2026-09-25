"""Small value types shared by several dryoc modules."""

from __future__ import annotations

import enum
from typing import NamedTuple

__all__ = ["EncryptedMessage", "Tag"]


class EncryptedMessage(NamedTuple):
    """A ciphertext together with the nonce it was encrypted with.

    Fields are ``(ciphertext, nonce)``, matching the argument order of
    ``decrypt(ciphertext, nonce)``, so a message unpacks straight into it::

        message = key.encrypt(b"data")
        key.decrypt(*message)

    The nonce is public: store or send it alongside the ciphertext.
    """

    ciphertext: bytes
    """The authenticated ciphertext."""
    nonce: bytes
    """The nonce used for encryption."""


class Tag(enum.IntFlag):
    """Tags that mark messages in a :mod:`dryoc.secretstream` stream."""

    MESSAGE = 0
    """An ordinary message."""
    PUSH = 1
    """Marks the end of a logical chunk (for example, the end of a record)."""
    REKEY = 2
    """Derives a new key after this message."""
    FINAL = PUSH | REKEY
    """The last message of the stream."""
