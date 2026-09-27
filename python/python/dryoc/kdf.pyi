from typing import ClassVar, Self, final

from typing_extensions import Buffer

__all__ = ["HkdfSha256", "HkdfSha512", "Kdf", "hkdf_sha256", "hkdf_sha512"]

@final
class Kdf:
    """Derives many independent subkeys from one master key (libsodium's
    `crypto_kdf`, BLAKE2b-based).

    Each subkey is identified by a numeric `subkey_id` and the 8-byte
    `context`, a constant describing its purpose in your application (for
    example `b"Sessions"`).
    """

    KEY_SIZE: ClassVar[int]
    """Length of the master key in bytes."""
    CONTEXT_SIZE: ClassVar[int]
    """Length of the context in bytes."""
    MIN_SUBKEY_SIZE: ClassVar[int]
    """Shortest subkey `derive` produces."""
    MAX_SUBKEY_SIZE: ClassVar[int]
    """Longest subkey `derive` produces."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer, context: Buffer) -> Self:
        """Creates a KDF from a 32-byte master `key` and an 8-byte `context`."""
    @classmethod
    def generate(cls, context: Buffer) -> Self:
        """Creates a KDF with a new random master key for `context`."""
    @property
    def context(self) -> bytes:
        """The context this KDF derives subkeys for."""
    def derive(self, subkey_id: int, length: int = 32) -> bytes:
        """Derives the subkey numbered `subkey_id` (0 to 2**64 - 1), `length`
        bytes long (16 to 64).
        """
    def __bytes__(self) -> bytes:
        """Exports the master key. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

class _Hkdf:
    """Interface shared by the HKDF keys (stub only; not a runtime class)."""

    SIZE: ClassVar[int]
    """Length of the key in bytes."""
    MAX_OUTPUT_SIZE: ClassVar[int]
    """Longest output `expand` produces."""
    __hash__: ClassVar[None]
    def __new__(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self:
        """Creates the key from its raw bytes."""
    @classmethod
    def generate(cls) -> Self:
        """Generates a new random key."""
    @classmethod
    def extract(cls, ikm: Buffer, *, salt: Buffer | None = None) -> Self:
        """HKDF-Extract: condenses input keying material `ikm` (and an
        optional, ideally random, `salt`) into a pseudorandom key.
        """
    def expand(self, info: Buffer | None = None, length: int = 32) -> bytes:
        """HKDF-Expand: derives `length` bytes bound to `info`."""
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class HkdfSha256(_Hkdf):
    """An HKDF-SHA-256 (RFC 5869) pseudorandom key, ready to expand.

    Create it with `extract()`, or from an existing 32-byte PRK.
    """

@final
class HkdfSha512(_Hkdf):
    """An HKDF-SHA-512 (RFC 5869) pseudorandom key, ready to expand.

    Create it with `extract()`, or from an existing 64-byte PRK.
    """

def hkdf_sha256(
    ikm: Buffer, *, salt: Buffer | None = None, info: Buffer | None = None, length: int = 32
) -> bytes:
    """One-shot HKDF-SHA-256: extract from `ikm` and `salt`, then expand `length` bytes bound to `info`."""

def hkdf_sha512(
    ikm: Buffer, *, salt: Buffer | None = None, info: Buffer | None = None, length: int = 32
) -> bytes:
    """One-shot HKDF-SHA-512: extract from `ikm` and `salt`, then expand `length` bytes bound to `info`."""
