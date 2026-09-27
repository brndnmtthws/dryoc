from typing import ClassVar, Self, final

from typing_extensions import Buffer

__all__ = [
    "Blake2b",
    "Sha3_256",
    "Sha3_512",
    "Sha256",
    "Sha512",
    "Shake128",
    "Shake128Reader",
    "Shake256",
    "Shake256Reader",
    "TurboShake128",
    "TurboShake128Reader",
    "TurboShake256",
    "TurboShake256Reader",
    "blake2b",
    "sha3_256",
    "sha3_512",
    "sha256",
    "sha512",
    "shake128",
    "shake256",
    "turboshake128",
    "turboshake256",
]

class _Hash:
    """Interface shared by the fixed-length hashes (stub only; not a runtime class)."""

    digest_size: ClassVar[int]
    """Digest length in bytes."""
    block_size: ClassVar[int]
    """Internal block length in bytes."""
    name: ClassVar[str]
    """The algorithm's `hashlib` name."""
    def __new__(cls, data: Buffer | None = None) -> Self:
        """Starts a new hash, optionally absorbing `data`."""
    def update(self, data: Buffer) -> None:
        """Absorbs more `data`."""
    def digest(self) -> bytes:
        """Returns the digest of everything absorbed so far. The hasher can
        keep absorbing afterwards.
        """
    def hexdigest(self) -> str:
        """Returns `digest()` as a lowercase hexadecimal string."""
    def copy(self) -> Self:
        """Returns an independent copy of the hasher."""

@final
class Sha256(_Hash):
    """Incremental SHA-256 (FIPS 180-4) with the `hashlib` interface."""

@final
class Sha512(_Hash):
    """Incremental SHA-512 (FIPS 180-4) with the `hashlib` interface."""

@final
class Sha3_256(_Hash):
    """Incremental SHA3-256 (FIPS 202) with the `hashlib` interface."""

@final
class Sha3_512(_Hash):
    """Incremental SHA3-512 (FIPS 202) with the `hashlib` interface."""

@final
class Blake2b:
    """Incremental BLAKE2b (libsodium's `crypto_generichash`) with the `hashlib`
    interface.

    `digest_size` defaults to 32 bytes as in libsodium, not 64 as in
    `hashlib.blake2b`. An optional `key` (up to 64 bytes, 32 recommended) makes
    it a MAC.
    """

    block_size: ClassVar[int]
    """Internal block length in bytes."""
    name: ClassVar[str]
    """The algorithm's `hashlib` name."""
    MAX_DIGEST_SIZE: ClassVar[int]
    """Largest supported `digest_size`."""
    MAX_KEY_SIZE: ClassVar[int]
    """Largest supported key length."""
    def __new__(
        cls, data: Buffer | None = None, *, digest_size: int = 32, key: Buffer | None = None
    ) -> Self:
        """Starts a new hash, optionally absorbing `data`."""
    @property
    def digest_size(self) -> int:
        """Digest length in bytes."""
    def update(self, data: Buffer) -> None:
        """Absorbs more `data`."""
    def digest(self) -> bytes:
        """Returns the digest of everything absorbed so far. The hasher can keep
        absorbing afterwards.
        """
    def hexdigest(self) -> str:
        """Returns `digest()` as a lowercase hexadecimal string."""
    def copy(self) -> Self:
        """Returns an independent copy of the hasher."""

class _Reader:
    """Interface shared by the XOF readers (stub only; not a runtime class)."""

    def read(self, length: int) -> bytes:
        """Returns the next `length` output bytes."""

@final
class Shake128Reader(_Reader):
    """Streaming output of a finished `Shake128`."""

@final
class Shake256Reader(_Reader):
    """Streaming output of a finished `Shake256`."""

@final
class TurboShake128Reader(_Reader):
    """Streaming output of a finished `TurboShake128`."""

@final
class TurboShake256Reader(_Reader):
    """Streaming output of a finished `TurboShake256`."""

class _Xof:
    """Interface shared by the extendable-output functions (stub only; not a runtime class)."""

    digest_size: ClassVar[int]
    """Always 0: the output length is chosen per call."""
    block_size: ClassVar[int]
    """Sponge rate in bytes."""
    name: ClassVar[str]
    """The algorithm's name."""
    def __new__(cls, data: Buffer | None = None, *, domain: int = 31) -> Self:
        """Starts a new hash, optionally absorbing `data`. `domain` is the
        domain-separation byte (0x01 to 0x7f); the default is the
        standard one, and others give unrelated outputs.
        """
    def update(self, data: Buffer) -> None:
        """Absorbs more `data`."""
    def digest(self, length: int) -> bytes:
        """Returns the first `length` output bytes for everything absorbed so
        far. The hasher can keep absorbing afterwards.
        """
    def hexdigest(self, length: int) -> str:
        """Returns `digest(length)` as a lowercase hexadecimal string."""
    def copy(self) -> Self:
        """Returns an independent copy of the hasher."""

@final
class Shake128(_Xof):
    """Incremental SHAKE128 (FIPS 202), like `hashlib.shake_128`."""

    def reader(self) -> Shake128Reader:
        """Returns a reader that streams the output for everything absorbed
        so far: successive `read` calls continue the same output. The
        hasher can keep absorbing afterwards.
        """

@final
class Shake256(_Xof):
    """Incremental SHAKE256 (FIPS 202), like `hashlib.shake_256`."""

    def reader(self) -> Shake256Reader:
        """Returns a reader that streams the output for everything absorbed
        so far: successive `read` calls continue the same output. The
        hasher can keep absorbing afterwards.
        """

@final
class TurboShake128(_Xof):
    """Incremental TurboSHAKE128 (RFC 9861): SHAKE128's sponge with 12 rounds."""

    def reader(self) -> TurboShake128Reader:
        """Returns a reader that streams the output for everything absorbed
        so far: successive `read` calls continue the same output. The
        hasher can keep absorbing afterwards.
        """

@final
class TurboShake256(_Xof):
    """Incremental TurboSHAKE256 (RFC 9861): SHAKE256's sponge with 12 rounds."""

    def reader(self) -> TurboShake256Reader:
        """Returns a reader that streams the output for everything absorbed
        so far: successive `read` calls continue the same output. The
        hasher can keep absorbing afterwards.
        """

def sha256(data: Buffer) -> bytes:
    """Returns the sha256 digest of `data`."""

def sha512(data: Buffer) -> bytes:
    """Returns the sha512 digest of `data`."""

def sha3_256(data: Buffer) -> bytes:
    """Returns the sha3_256 digest of `data`."""

def sha3_512(data: Buffer) -> bytes:
    """Returns the sha3_512 digest of `data`."""

def blake2b(data: Buffer, *, digest_size: int = 32, key: Buffer | None = None) -> bytes:
    """Returns the BLAKE2b digest of `data` (libsodium's `crypto_generichash`).

    `digest_size` defaults to 32 bytes; `key` (up to 64 bytes) makes it a MAC.
    """

def shake128(data: Buffer, length: int, *, domain: int = 31) -> bytes:
    """Returns `length` bytes of shake_128 output for `data` with the domain-separation byte `domain`."""

def shake256(data: Buffer, length: int, *, domain: int = 31) -> bytes:
    """Returns `length` bytes of shake_256 output for `data` with the domain-separation byte `domain`."""

def turboshake128(data: Buffer, length: int, *, domain: int = 31) -> bytes:
    """Returns `length` bytes of turboshake128 output for `data` with the domain-separation byte `domain`."""

def turboshake256(data: Buffer, length: int, *, domain: int = 31) -> bytes:
    """Returns `length` bytes of turboshake256 output for `data` with the domain-separation byte `domain`."""
