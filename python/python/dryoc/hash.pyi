from typing import ClassVar, final

from typing_extensions import Buffer, Self

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
    digest_size: ClassVar[int]
    block_size: ClassVar[int]
    name: ClassVar[str]
    def __new__(cls, data: Buffer | None = None) -> Self: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> Self: ...

@final
class Sha256(_Hash):
    """Incremental SHA-256."""

@final
class Sha512(_Hash):
    """Incremental SHA-512."""

@final
class Sha3_256(_Hash):
    """Incremental SHA3-256."""

@final
class Sha3_512(_Hash):
    """Incremental SHA3-512."""

@final
class Blake2b:
    """Incremental BLAKE2b (libsodium's ``crypto_generichash``)."""

    block_size: ClassVar[int]
    name: ClassVar[str]
    MAX_DIGEST_SIZE: ClassVar[int]
    MAX_KEY_SIZE: ClassVar[int]
    def __new__(
        cls, data: Buffer | None = None, *, digest_size: int = 32, key: Buffer | None = None
    ) -> Self: ...
    @property
    def digest_size(self) -> int: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> Self: ...

class _Reader:
    def read(self, length: int) -> bytes: ...

@final
class Shake128Reader(_Reader):
    """Streaming SHAKE128 output."""

@final
class Shake256Reader(_Reader):
    """Streaming SHAKE256 output."""

@final
class TurboShake128Reader(_Reader):
    """Streaming TurboSHAKE128 output."""

@final
class TurboShake256Reader(_Reader):
    """Streaming TurboSHAKE256 output."""

class _Xof:
    digest_size: ClassVar[int]
    block_size: ClassVar[int]
    name: ClassVar[str]
    def __new__(cls, data: Buffer | None = None, *, domain: int = 31) -> Self: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self, length: int) -> bytes: ...
    def hexdigest(self, length: int) -> str: ...
    def copy(self) -> Self: ...

@final
class Shake128(_Xof):
    """Incremental SHAKE128."""

    def reader(self) -> Shake128Reader: ...

@final
class Shake256(_Xof):
    """Incremental SHAKE256."""

    def reader(self) -> Shake256Reader: ...

@final
class TurboShake128(_Xof):
    """Incremental TurboSHAKE128."""

    def reader(self) -> TurboShake128Reader: ...

@final
class TurboShake256(_Xof):
    """Incremental TurboSHAKE256."""

    def reader(self) -> TurboShake256Reader: ...

def sha256(data: Buffer) -> bytes: ...
def sha512(data: Buffer) -> bytes: ...
def sha3_256(data: Buffer) -> bytes: ...
def sha3_512(data: Buffer) -> bytes: ...
def blake2b(data: Buffer, *, digest_size: int = 32, key: Buffer | None = None) -> bytes: ...
def shake128(data: Buffer, length: int, *, domain: int = 31) -> bytes: ...
def shake256(data: Buffer, length: int, *, domain: int = 31) -> bytes: ...
def turboshake128(data: Buffer, length: int, *, domain: int = 31) -> bytes: ...
def turboshake256(data: Buffer, length: int, *, domain: int = 31) -> bytes: ...
