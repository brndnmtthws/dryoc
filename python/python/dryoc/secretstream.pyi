from types import TracebackType
from typing import ClassVar, Self, final

from typing_extensions import Buffer

from dryoc._types import Tag as Tag

__all__ = ["Decryptor", "Encryptor", "Key", "Tag"]

@final
class Key:
    """A secret key for an encrypted stream."""

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
    def __bytes__(self) -> bytes:
        """Exports the raw key bytes. Handle the result as a secret."""
    def __eq__(self, value: object, /) -> bool: ...

@final
class Encryptor:
    """Encrypts an ordered sequence of messages.

    Send `header` to the receiver before the ciphertexts. Mark the last message
    with `Tag.FINAL`; after it, the encryptor refuses further messages. Used as
    a context manager, it wipes its state on exit and raises `DryocError` if the
    block finished without a `Tag.FINAL` message.
    """

    HEADER_SIZE: ClassVar[int]
    """Length of the stream header in bytes."""
    OVERHEAD: ClassVar[int]
    """Bytes each ciphertext adds to its message."""
    def __new__(cls, key: Key) -> Self:
        """Starts a new stream under `key` with a fresh random header."""
    @property
    def header(self) -> bytes:
        """The public stream header. The receiver needs it to decrypt."""
    @property
    def finished(self) -> bool:
        """Whether a `Tag.FINAL` message has been pushed."""
    def push(
        self, message: Buffer, *, tag: Tag | int = ..., associated_data: Buffer | None = None
    ) -> bytes:
        """Encrypts the next `message`, returning its ciphertext.

        `tag` marks the message; `Tag.FINAL` ends the stream. `associated_data`
        is authenticated but not encrypted, and must be passed again to `pull`.
        """
    def rekey(self) -> None:
        """Derives a new key for the following messages without sending a
        message. The receiver must call `rekey()` at the same point.
        """
    def close(self) -> None:
        """Wipes the stream state. Further `push` calls raise `DryocError`.

        Closing never raises, even if no `Tag.FINAL` message was pushed; check
        `finished` first, or use the encryptor as a context manager, whose exit
        raises for an unfinished stream even after an explicit `close()`.
        """
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool: ...

@final
class Decryptor:
    """Decrypts and authenticates a stream produced by `Encryptor`.

    Messages must be pulled in the order they were pushed; a modified,
    reordered, duplicated or dropped message raises `CryptoError`. Truncation
    is only detectable through `Tag.FINAL`: check `finished`, or use the
    decryptor as a context manager, which wipes its state on exit and raises
    `CryptoError` if the block finished before a `Tag.FINAL` message arrived.
    """

    HEADER_SIZE: ClassVar[int]
    """Length of the stream header in bytes."""
    OVERHEAD: ClassVar[int]
    """Bytes each ciphertext adds to its message."""
    def __new__(cls, key: Key, header: Buffer) -> Self:
        """Starts decrypting the stream identified by `header` under `key`."""
    @property
    def finished(self) -> bool:
        """Whether the `Tag.FINAL` message has been pulled."""
    def pull(
        self, ciphertext: Buffer, *, associated_data: Buffer | None = None
    ) -> tuple[bytes, Tag]:
        """Decrypts the next `ciphertext`, returning `(message, tag)`.

        Raises `CryptoError` if the ciphertext is not the next authentic
        message of this stream (the stream state is left unchanged), or if it
        follows the `Tag.FINAL` message.
        """
    def rekey(self) -> None:
        """Derives a new key at the point where the sender called `rekey()`."""
    def close(self) -> None:
        """Wipes the stream state. Further `pull` calls raise `DryocError`.

        Closing never raises, even before the `Tag.FINAL` message arrived; the
        caller must then check `finished` to detect truncation. Used as a
        context manager, the decryptor's exit raises `CryptoError` for an
        unfinished stream even after an explicit `close()`.
        """
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool: ...
