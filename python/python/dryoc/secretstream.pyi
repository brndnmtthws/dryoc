from types import TracebackType
from typing import ClassVar, final

from typing_extensions import Buffer, Self

from dryoc._types import Tag as Tag

__all__ = ["Decryptor", "Encryptor", "Key", "Tag"]

@final
class Key:
    """A secret key for an encrypted stream."""

    SIZE: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, key: Buffer) -> Self: ...
    @classmethod
    def from_bytes(cls, key: Buffer) -> Self: ...
    @classmethod
    def generate(cls) -> Self: ...
    def __bytes__(self) -> bytes: ...
    def __eq__(self, value: object, /) -> bool: ...

@final
class Encryptor:
    """Encrypts an ordered sequence of messages."""

    HEADER_SIZE: ClassVar[int]
    OVERHEAD: ClassVar[int]
    def __new__(cls, key: Key) -> Self: ...
    @property
    def header(self) -> bytes: ...
    @property
    def finished(self) -> bool: ...
    def push(
        self, message: Buffer, *, tag: Tag | int = ..., associated_data: Buffer | None = None
    ) -> bytes: ...
    def rekey(self) -> None: ...
    def close(self) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool: ...

@final
class Decryptor:
    """Decrypts and authenticates a stream produced by :class:`Encryptor`."""

    HEADER_SIZE: ClassVar[int]
    OVERHEAD: ClassVar[int]
    def __new__(cls, key: Key, header: Buffer) -> Self: ...
    @property
    def finished(self) -> bool: ...
    def pull(
        self, ciphertext: Buffer, *, associated_data: Buffer | None = None
    ) -> tuple[bytes, Tag]: ...
    def rekey(self) -> None: ...
    def close(self) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool: ...
