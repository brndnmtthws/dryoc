from typing import ClassVar, Self, final

from typing_extensions import Buffer

__all__ = [
    "HmacSha256",
    "HmacSha512",
    "HmacSha512256",
    "Poly1305",
    "hmac_sha256",
    "hmac_sha512",
    "hmac_sha512256",
    "poly1305",
]

class _Mac:
    KEY_SIZE: ClassVar[int]
    digest_size: ClassVar[int]
    block_size: ClassVar[int]
    name: ClassVar[str]
    @classmethod
    def generate_key(cls) -> bytes: ...
    def __new__(cls, key: Buffer, data: Buffer | None = None) -> Self: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def verify(self, tag: Buffer) -> None: ...

@final
class HmacSha256(_Mac):
    """HMAC-SHA-256 with a 32-byte key."""

@final
class HmacSha512(_Mac):
    """HMAC-SHA-512 with a 32-byte key."""

@final
class HmacSha512256(_Mac):
    """HMAC-SHA-512-256, libsodium's ``crypto_auth``."""

@final
class Poly1305(_Mac):
    """Poly1305 one-time authenticator (``crypto_onetimeauth``)."""

def hmac_sha256(key: Buffer, data: Buffer) -> bytes: ...
def hmac_sha512(key: Buffer, data: Buffer) -> bytes: ...
def hmac_sha512256(key: Buffer, data: Buffer) -> bytes: ...
def poly1305(key: Buffer, data: Buffer) -> bytes: ...
