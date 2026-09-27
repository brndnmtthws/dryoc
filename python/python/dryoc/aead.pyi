from typing import ClassVar, Self, final

from typing_extensions import Buffer

from dryoc._types import EncryptedMessage as EncryptedMessage

__all__ = ["ChaCha20Poly1305", "EncryptedMessage", "XChaCha20Poly1305"]

@final
class XChaCha20Poly1305:
    """A key for XChaCha20-Poly1305-IETF (libsodium's
    `crypto_aead_xchacha20poly1305_ietf`).

    Its 192-bit nonces are safe to generate at random, so `encrypt` and
    `seal` do so by default.
    """

    KEY_SIZE: ClassVar[int]
    """Length of the key in bytes."""
    NONCE_SIZE: ClassVar[int]
    """Length of a nonce in bytes."""
    TAG_SIZE: ClassVar[int]
    """Length of the authentication tag appended to each ciphertext."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random key."""
    def encrypt(
        self,
        plaintext: Buffer,
        nonce: Buffer | None = None,
        *,
        associated_data: Buffer | None = None,
    ) -> EncryptedMessage:
        """Encrypts `plaintext`, returning `EncryptedMessage(ciphertext, nonce)`.

        The ciphertext is libsodium's format (encrypted data then tag). A
        random nonce is generated when `nonce` is omitted. `associated_data`
        is authenticated but not encrypted, and must be passed again to
        `decrypt`.
        """
    def decrypt(
        self, ciphertext: Buffer, nonce: Buffer, *, associated_data: Buffer | None = None
    ) -> bytes:
        """Decrypts and authenticates `ciphertext` produced with `nonce`.

        Raises `CryptoError` if the key, nonce, ciphertext or associated data
        is wrong.
        """
    def seal(self, plaintext: Buffer, *, associated_data: Buffer | None = None) -> bytes:
        """Encrypts `plaintext` under a fresh random nonce and returns the
        self-contained envelope `nonce || ciphertext || tag`.
        """
    def open(self, envelope: Buffer, *, associated_data: Buffer | None = None) -> bytes:
        """Opens an envelope produced by `seal`, returning the plaintext.

        Raises `CryptoError` if the envelope was modified or the key or
        associated data is wrong.
        """
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class ChaCha20Poly1305:
    """A key for ChaCha20-Poly1305-IETF (RFC 8439, libsodium's
    `crypto_aead_chacha20poly1305_ietf`).

    Its 96-bit nonces are too short to pick at random safely, so every call
    takes an explicit nonce, which must never repeat under one key. Prefer
    `XChaCha20Poly1305` unless a protocol requires this variant.
    """

    KEY_SIZE: ClassVar[int]
    """Length of the key in bytes."""
    NONCE_SIZE: ClassVar[int]
    """Length of a nonce in bytes."""
    TAG_SIZE: ClassVar[int]
    """Length of the authentication tag appended to each ciphertext."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random key."""
    def encrypt(
        self, plaintext: Buffer, nonce: Buffer, *, associated_data: Buffer | None = None
    ) -> EncryptedMessage:
        """Encrypts `plaintext` with `nonce`, returning
        `EncryptedMessage(ciphertext, nonce)`.

        The ciphertext is the encrypted data followed by the tag.
        """
    def decrypt(
        self, ciphertext: Buffer, nonce: Buffer, *, associated_data: Buffer | None = None
    ) -> bytes:
        """Decrypts and authenticates `ciphertext` produced with `nonce`.

        Raises `CryptoError` if the key, nonce, ciphertext or associated data
        is wrong.
        """
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...
