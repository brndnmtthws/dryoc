"""ML-KEM-768 key encapsulation (FIPS 203)."""

from typing import ClassVar, Self, final

from typing_extensions import Buffer

__all__ = ["KeyPair", "PublicKey", "SecretKey"]

@final
class PublicKey:
    """An ML-KEM-768 (FIPS 203) public key."""

    SIZE: ClassVar[int]
    """Length of the key in bytes."""
    CIPHERTEXT_SIZE: ClassVar[int]
    """Length of a ciphertext produced by `encapsulate` in bytes."""
    SHARED_SECRET_SIZE: ClassVar[int]
    """Length of the shared secret in bytes."""
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    def encapsulate(self) -> tuple[bytes, bytes]:
        """Creates a fresh random shared secret for this key's owner.

        Returns `(ciphertext, shared_secret)`: send the ciphertext to the
        key's owner, who recovers the same secret with
        `KeyPair.decapsulate`. Pass the secret through a KDF before
        using it as a key.
        """
    def __bytes__(self) -> bytes:
        """Returns the raw key bytes."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class SecretKey:
    """An ML-KEM-768 (FIPS 203) secret key. Most code uses a `KeyPair` instead.

    Generate keys with `KeyPair.generate()`; this class only wraps
    existing key bytes.
    """

    SIZE: ClassVar[int]
    """Length of the key in bytes."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer) -> Self:
        """Wraps existing secret key bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Wraps existing secret key bytes."""
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class KeyPair:
    """An ML-KEM-768 (FIPS 203) key pair.

    Create one with `generate()`, `from_seed()` or `from_secret_key()`.
    The repr never shows the secret key; export it deliberately with
    `bytes(pair.secret_key)`.
    """

    SEED_SIZE: ClassVar[int]
    """Length of a seed accepted by `from_seed` in bytes."""
    __hash__: ClassVar[None]
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random key pair."""
    @classmethod
    def from_seed(cls, seed: Buffer) -> Self:
        """Deterministically derives a key pair from `seed`."""
    @classmethod
    def from_secret_key(cls, secret_key: SecretKey | Buffer) -> Self:
        """Rebuilds a key pair from a secret key (a `SecretKey` or its raw
        bytes), deriving the public key.
        """
    @property
    def public_key(self) -> PublicKey:
        """The public key; share it freely."""
    @property
    def secret_key(self) -> SecretKey:
        """The secret key; keep it private."""
    def decapsulate(self, ciphertext: Buffer) -> bytes:
        """Recovers the shared secret from a `ciphertext` made by
        `PublicKey.encapsulate`.

        A modified ciphertext does not raise: ML-KEM's implicit rejection
        returns an unrelated secret instead, so the mismatch surfaces when
        the derived key fails to authenticate.
        """
    def __eq__(self, value: object, /) -> bool: ...
