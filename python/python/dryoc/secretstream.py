"""Encrypted streams of messages, compatible with libsodium's
``crypto_secretstream_xchacha20poly1305``.

Example::

    from dryoc.secretstream import Decryptor, Encryptor, Key, Tag

    key = Key.generate()
    with Encryptor(key) as encryptor:
        header = encryptor.header
        chunks = [encryptor.push(b"part 1"), encryptor.push(b"part 2", tag=Tag.FINAL)]

    with Decryptor(key, header) as decryptor:
        for chunk in chunks:
            message, tag = decryptor.pull(chunk)
"""

from __future__ import annotations

from dryoc._dryoc import secretstream_Decryptor as Decryptor
from dryoc._dryoc import secretstream_Encryptor as Encryptor
from dryoc._dryoc import secretstream_Key as Key
from dryoc._types import Tag

__all__ = ["Decryptor", "Encryptor", "Key", "Tag"]
