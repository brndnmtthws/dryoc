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
    """Interface shared by the MACs (stub only; not a runtime class)."""

    KEY_SIZE: ClassVar[int]
    """Length of the key in bytes."""
    digest_size: ClassVar[int]
    """Length of the tag in bytes."""
    block_size: ClassVar[int]
    """Internal block length in bytes."""
    name: ClassVar[str]
    """The algorithm's name."""
    @classmethod
    def generate_key(cls) -> bytes:
        """Returns a new random key."""
    def __new__(cls, key: Buffer, data: Buffer | None = None) -> Self:
        """Starts authenticating under `key`, optionally absorbing `data`."""
    def update(self, data: Buffer) -> None:
        """Absorbs more `data`. Raises `DryocError` once finalized."""
    def digest(self) -> bytes:
        """Finalizes (on the first call) and returns the tag."""
    def hexdigest(self) -> str:
        """Returns `digest()` as a lowercase hexadecimal string."""
    def verify(self, tag: Buffer) -> None:
        """Finalizes (on the first call) and checks `tag` in constant time.

        Raises `CryptoError` if it does not match.
        """

@final
class HmacSha256(_Mac):
    """HMAC-SHA-256 (RFC 2104 / FIPS 198-1) with a 32-byte key."""

@final
class HmacSha512(_Mac):
    """HMAC-SHA-512 (RFC 2104 / FIPS 198-1) with a 32-byte key."""

@final
class HmacSha512256(_Mac):
    """HMAC-SHA-512-256: HMAC-SHA-512 truncated to 32 bytes, libsodium's
    default `crypto_auth` MAC.
    """

@final
class Poly1305(_Mac):
    """Poly1305 one-time authenticator (libsodium's `crypto_onetimeauth`).

    A Poly1305 key must authenticate only ONE message; reusing it lets an
    attacker forge tags. Use an HMAC unless you derive a fresh key per
    message.
    """

def hmac_sha256(key: Buffer, data: Buffer) -> bytes:
    """Returns the hmac-sha256 tag of `data` under `key`."""

def hmac_sha512(key: Buffer, data: Buffer) -> bytes:
    """Returns the hmac-sha512 tag of `data` under `key`."""

def hmac_sha512256(key: Buffer, data: Buffer) -> bytes:
    """Returns the hmac-sha512-256 tag of `data` under `key`."""

def poly1305(key: Buffer, data: Buffer) -> bytes:
    """Returns the poly1305 tag of `data` under `key`."""
