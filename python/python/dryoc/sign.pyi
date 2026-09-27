from typing import ClassVar, Self, final

from typing_extensions import Buffer

__all__ = ["Ed25519ph", "SigningKey", "VerifyKey"]

@final
class VerifyKey:
    """An Ed25519 public key, used to verify signatures."""

    SIZE: ClassVar[int]
    """Length of the key in bytes."""
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    def verify(self, signature: Buffer, message: Buffer) -> None:
        """Checks a detached Ed25519 `signature` over `message`.

        Raises `CryptoError` if the signature is invalid.
        """
    def verify_combined(self, signed_message: Buffer) -> bytes:
        """Checks a combined `signature || message` (libsodium's `crypto_sign`
        format) and returns the message.

        Raises `CryptoError` if the signature is invalid.
        """
    def __bytes__(self) -> bytes:
        """Returns the raw key bytes."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class SigningKey:
    """An Ed25519 signing key.

    Its raw form (`bytes(key)`, 64 bytes) is libsodium's secret key: the
    32-byte seed followed by the public key. The repr never shows it.
    """

    SIZE: ClassVar[int]
    """Length of the raw (libsodium) secret key in bytes."""
    SEED_SIZE: ClassVar[int]
    """Length of a seed in bytes."""
    SIGNATURE_SIZE: ClassVar[int]
    """Length of a signature in bytes."""
    __hash__: ClassVar[None]
    def __new__(cls, secret_key: Buffer) -> Self:
        """Loads a 64-byte libsodium secret key. The public half is recomputed
        from the seed.
        """
    @classmethod
    def from_bytes(cls, secret_key: Buffer) -> Self:
        """Loads a 64-byte libsodium secret key. The public half is recomputed
        from the seed.
        """
    @classmethod
    def from_seed(cls, seed: Buffer) -> Self:
        """Deterministically derives a signing key from a 32-byte `seed`."""
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random signing key."""
    @property
    def verify_key(self) -> VerifyKey:
        """The matching public key."""
    def to_seed(self) -> bytes:
        """Exports the 32-byte seed. Handle the result as a secret."""
    def sign(self, message: Buffer) -> bytes:
        """Returns the 64-byte detached Ed25519 signature of `message`."""
    def sign_combined(self, message: Buffer) -> bytes:
        """Returns `signature || message` (libsodium's `crypto_sign` format)."""
    def __bytes__(self) -> bytes:
        """Exports the 64-byte libsodium secret key. Handle it as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class Ed25519ph:
    """Incremental Ed25519ph (pre-hashed Ed25519, RFC 8032) for messages too
    large to hold in memory.

    Ed25519ph signatures differ from Ed25519 ones: verify them with
    `Ed25519ph`, not `VerifyKey.verify`. An instance produces or checks one
    signature; afterwards it raises `DryocError`.
    """

    def __new__(cls, data: Buffer | None = None) -> Self:
        """Starts a new message, optionally absorbing `data`."""
    def update(self, data: Buffer) -> None:
        """Absorbs the next part of the message."""
    def sign(self, signing_key: SigningKey) -> bytes:
        """Signs the absorbed message, returning a 64-byte signature."""
    def verify(self, signature: Buffer, verify_key: VerifyKey) -> None:
        """Checks `signature` over the absorbed message.

        Raises `CryptoError` if the signature is invalid.
        """
