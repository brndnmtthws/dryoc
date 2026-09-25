from collections.abc import Iterator
from typing import ClassVar, final

from dryoc.box import KeyPair as KeyPair
from dryoc.box import PublicKey as PublicKey

__all__ = ["KeyPair", "PublicKey", "SessionKeys", "client_session_keys", "server_session_keys"]

@final
class SessionKeys:
    """A pair of session keys; unpacks as ``rx, tx``."""

    __hash__: ClassVar[None]  # type: ignore[assignment]
    @property
    def rx(self) -> bytes: ...
    @property
    def tx(self) -> bytes: ...
    def __iter__(self) -> Iterator[bytes]: ...
    def __eq__(self, value: object, /) -> bool: ...

def client_session_keys(client: KeyPair, server_public_key: PublicKey) -> SessionKeys: ...
def server_session_keys(server: KeyPair, client_public_key: PublicKey) -> SessionKeys: ...
