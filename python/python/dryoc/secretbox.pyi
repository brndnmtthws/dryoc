from typing import ClassVar, Self, final

from typing_extensions import Buffer

from dryoc._types import EncryptedMessage as EncryptedMessage

__all__ = ["EncryptedMessage", "SecretBox"]

@final
class SecretBox:
    """A secret key for XSalsa20-Poly1305 authenticated encryption
    (libsodium's `crypto_secretbox`).
    """

    KEY_SIZE: ClassVar[int]
    """Length of the key in bytes."""
    NONCE_SIZE: ClassVar[int]
    """Length of a nonce in bytes."""
    MAC_SIZE: ClassVar[int]
    """Length of the authentication tag added to each message."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random key."""
    def encrypt(self, plaintext: Buffer, nonce: Buffer | None = None) -> EncryptedMessage:
        """Encrypts `plaintext`, returning `EncryptedMessage(ciphertext, nonce)`.

        A random nonce is generated when `nonce` is omitted. The ciphertext is
        libsodium's `crypto_secretbox_easy` format (tag then encrypted data).
        """
    def decrypt(self, ciphertext: Buffer, nonce: Buffer) -> bytes:
        """Decrypts and authenticates `ciphertext` produced with `nonce`.

        Raises `CryptoError` if the key, nonce or ciphertext is wrong.
        """
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...
