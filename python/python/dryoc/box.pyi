from typing import ClassVar, Self, final

from typing_extensions import Buffer

from dryoc._types import EncryptedMessage as EncryptedMessage

__all__ = ["Box", "EncryptedMessage", "KeyPair", "PublicKey", "SealedBox", "SecretKey"]

@final
class PublicKey:
    """An X25519 public key, used with `Box`, `SealedBox` and `dryoc.kx`."""

    SIZE: ClassVar[int]
    """Length of the key in bytes."""
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    def __bytes__(self) -> bytes:
        """Returns the raw key bytes."""
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class SecretKey:
    """An X25519 secret key. Most code uses a `KeyPair` instead."""

    SIZE: ClassVar[int]
    """Length of the key in bytes."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random key."""
    @property
    def public_key(self) -> PublicKey:
        """The public key matching this secret key."""
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class KeyPair:
    """An X25519 key pair for `Box`, `SealedBox` and `dryoc.kx`.

    Create one with `generate()`, `from_seed()` or `from_secret_key()`. The
    repr never shows the secret key; export it deliberately with
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
        """Deterministically derives a key pair from a 32-byte `seed`
        (libsodium's `crypto_box_seed_keypair`).
        """
    @classmethod
    def from_secret_key(cls, secret_key: SecretKey | Buffer) -> Self:
        """Rebuilds a key pair from a secret key (a `SecretKey` or its 32 raw
        bytes), deriving the public key.
        """
    @property
    def public_key(self) -> PublicKey:
        """The public key; share it freely."""
    @property
    def secret_key(self) -> SecretKey:
        """The secret key; keep it private."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class Box:
    """Authenticated encryption between two parties (libsodium's `crypto_box`).

    `Box(my_secret, their_public_key)` precomputes the shared key once, so
    repeated messages are cheap. Both directions share one nonce space: a nonce
    must never repeat for the same pair of keys. The random nonces `encrypt`
    generates by default satisfy that.
    """

    NONCE_SIZE: ClassVar[int]
    """Length of a nonce in bytes."""
    MAC_SIZE: ClassVar[int]
    """Length of the authentication tag added to each message."""
    __hash__: ClassVar[None]
    def __new__(cls, secret_key: KeyPair | SecretKey, public_key: PublicKey) -> Self:
        """Creates a box from your secret key (`KeyPair` or `SecretKey`) and the
        other party's `PublicKey`.

        Raises `InvalidInputError` if `public_key` is a low-order point.
        """
    def encrypt(self, plaintext: Buffer, nonce: Buffer | None = None) -> EncryptedMessage:
        """Encrypts `plaintext`, returning `EncryptedMessage(ciphertext, nonce)`.

        A random nonce is generated when `nonce` is omitted. The ciphertext is
        libsodium's `crypto_box_easy` format (tag then encrypted data).
        """
    def decrypt(self, ciphertext: Buffer, nonce: Buffer) -> bytes:
        """Decrypts and authenticates `ciphertext` produced with `nonce`.

        Raises `CryptoError` if the keys, nonce or ciphertext are wrong.
        """

@final
class SealedBox:
    """Anonymous public-key encryption (libsodium's `crypto_box_seal`).

    Anyone with the recipient's `PublicKey` can encrypt; only the holder of the
    `KeyPair` can decrypt. The sender stays anonymous and cannot decrypt their
    own message. For confidentiality against future quantum computers, use
    `dryoc.sealedbox.SealedBox` instead.
    """

    OVERHEAD: ClassVar[int]
    """Bytes a sealed box adds to the plaintext."""
    __hash__: ClassVar[None]
    def __new__(cls, recipient: PublicKey | KeyPair | SecretKey) -> Self:
        """Creates a sealed box for a recipient.

        Pass the recipient's `PublicKey` to encrypt only, or the recipient's
        `KeyPair` (or `SecretKey`) to also decrypt.
        """
    @property
    def public_key(self) -> PublicKey:
        """The recipient's public key."""
    def encrypt(self, plaintext: Buffer) -> bytes:
        """Encrypts `plaintext` for the recipient, returning
        `ephemeral_public_key || tag || ciphertext`.
        """
    def decrypt(self, ciphertext: Buffer) -> bytes:
        """Decrypts a sealed box. Requires the recipient's key pair.

        Raises `CryptoError` if the box was modified or is for another key.
        """
