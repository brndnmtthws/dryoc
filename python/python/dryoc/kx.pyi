from collections.abc import Iterator
from typing import ClassVar, final

from dryoc.box import KeyPair as KeyPair
from dryoc.box import PublicKey as PublicKey

__all__ = ["KeyPair", "PublicKey", "SessionKeys", "client_session_keys", "server_session_keys"]

@final
class SessionKeys:
    """A pair of session keys from `client_session_keys` or
    `server_session_keys`.

    Decrypt what the peer sends with `rx` and encrypt what you send with `tx`;
    `rx, tx = keys` unpacks both. The keys are wiped when the object is freed,
    compare in constant time, are not hashable, and never appear in the repr.
    """

    __hash__: ClassVar[None]
    @property
    def rx(self) -> bytes:
        """Key for receiving (decrypting) data from the peer. Handle it as a
        secret.
        """
    @property
    def tx(self) -> bytes:
        """Key for transmitting (encrypting) data to the peer. Handle it as a
        secret.
        """
    def __iter__(self) -> Iterator[bytes]: ...
    def __eq__(self, value: object, /) -> bool: ...

def client_session_keys(client: KeyPair, server_public_key: PublicKey) -> SessionKeys:
    """Computes the client's session keys for talking to the server with
    `server_public_key`.

    Returns `SessionKeys`: decrypt with `rx`, encrypt with `tx`. The server's
    `tx` equals the client's `rx` and vice versa. Raises `InvalidInputError` if
    `server_public_key` is a low-order point.
    """

def server_session_keys(server: KeyPair, client_public_key: PublicKey) -> SessionKeys:
    """Computes the server's session keys for talking to the client with
    `client_public_key`.

    Returns `SessionKeys`: decrypt with `rx`, encrypt with `tx`. Raises
    `InvalidInputError` if `client_public_key` is a low-order point.
    """
