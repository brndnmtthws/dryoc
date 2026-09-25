from typing import ClassVar, Self, final

from typing_extensions import Buffer

__all__ = ["HkdfSha256", "HkdfSha512", "Kdf", "hkdf_sha256", "hkdf_sha512"]

@final
class Kdf:
    """libsodium's BLAKE2b ``crypto_kdf`` subkey derivation."""

    KEY_SIZE: ClassVar[int]
    CONTEXT_SIZE: ClassVar[int]
    MIN_SUBKEY_SIZE: ClassVar[int]
    MAX_SUBKEY_SIZE: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, key: Buffer, context: Buffer) -> Self: ...
    @classmethod
    def generate(cls, context: Buffer) -> Self: ...
    @property
    def context(self) -> bytes: ...
    def derive(self, subkey_id: int, length: int = 32) -> bytes: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...

class _Hkdf:
    SIZE: ClassVar[int]
    MAX_OUTPUT_SIZE: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, key: Buffer) -> Self: ...
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self: ...
    @classmethod
    def generate(cls) -> Self: ...
    @classmethod
    def extract(cls, ikm: Buffer, *, salt: Buffer | None = None) -> Self: ...
    def expand(self, info: Buffer | None = None, length: int = 32) -> bytes: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...

@final
class HkdfSha256(_Hkdf):
    """An HKDF-SHA-256 pseudorandom key."""

@final
class HkdfSha512(_Hkdf):
    """An HKDF-SHA-512 pseudorandom key."""

def hkdf_sha256(
    ikm: Buffer, *, salt: Buffer | None = None, info: Buffer | None = None, length: int = 32
) -> bytes: ...
def hkdf_sha512(
    ikm: Buffer, *, salt: Buffer | None = None, info: Buffer | None = None, length: int = 32
) -> bytes: ...
