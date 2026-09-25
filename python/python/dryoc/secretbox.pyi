from typing import ClassVar, final

from typing_extensions import Buffer, Self

from dryoc._types import EncryptedMessage as EncryptedMessage

__all__ = ["EncryptedMessage", "SecretBox"]

@final
class SecretBox:
    """A secret key for XSalsa20-Poly1305 authenticated encryption
    (libsodium's ``crypto_secretbox``)."""

    KEY_SIZE: ClassVar[int]
    NONCE_SIZE: ClassVar[int]
    MAC_SIZE: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, key: Buffer) -> Self: ...
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self: ...
    @classmethod
    def generate(cls) -> Self: ...
    def encrypt(self, plaintext: Buffer, nonce: Buffer | None = None) -> EncryptedMessage: ...
    def decrypt(self, ciphertext: Buffer, nonce: Buffer) -> bytes: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...
