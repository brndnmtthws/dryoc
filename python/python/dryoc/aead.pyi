from typing import ClassVar, final

from typing_extensions import Buffer, Self

from dryoc._types import EncryptedMessage as EncryptedMessage

__all__ = ["ChaCha20Poly1305", "EncryptedMessage", "XChaCha20Poly1305"]

@final
class XChaCha20Poly1305:
    """A key for XChaCha20-Poly1305-IETF (random nonces are safe)."""

    KEY_SIZE: ClassVar[int]
    NONCE_SIZE: ClassVar[int]
    TAG_SIZE: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, key: Buffer) -> Self: ...
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self: ...
    @classmethod
    def generate(cls) -> Self: ...
    def encrypt(
        self,
        plaintext: Buffer,
        nonce: Buffer | None = None,
        *,
        associated_data: Buffer | None = None,
    ) -> EncryptedMessage: ...
    def decrypt(
        self, ciphertext: Buffer, nonce: Buffer, *, associated_data: Buffer | None = None
    ) -> bytes: ...
    def seal(self, plaintext: Buffer, *, associated_data: Buffer | None = None) -> bytes: ...
    def open(self, envelope: Buffer, *, associated_data: Buffer | None = None) -> bytes: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...

@final
class ChaCha20Poly1305:
    """A key for ChaCha20-Poly1305-IETF (RFC 8439); nonces are explicit."""

    KEY_SIZE: ClassVar[int]
    NONCE_SIZE: ClassVar[int]
    TAG_SIZE: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, key: Buffer) -> Self: ...
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self: ...
    @classmethod
    def generate(cls) -> Self: ...
    def encrypt(
        self, plaintext: Buffer, nonce: Buffer, *, associated_data: Buffer | None = None
    ) -> EncryptedMessage: ...
    def decrypt(
        self, ciphertext: Buffer, nonce: Buffer, *, associated_data: Buffer | None = None
    ) -> bytes: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...
