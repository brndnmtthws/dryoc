"""Message authentication codes: HMAC-SHA-256, HMAC-SHA-512,
HMAC-SHA-512-256 (libsodium's ``crypto_auth``) and Poly1305 (libsodium's
``crypto_onetimeauth``).

Classes follow the :mod:`hmac` interface (``update()``, ``digest()``,
``hexdigest()``) plus ``verify(tag)``, which compares in constant time and
raises :class:`~dryoc.CryptoError` on a mismatch. An object authenticates one
message: once finalized by ``digest()`` or ``verify()``, ``update()`` raises.

Example::

    from dryoc import mac

    key = mac.HmacSha512256.generate_key()
    tag = mac.hmac_sha512256(key, b"message")
    mac.HmacSha512256(key, b"message").verify(tag)
"""

from dryoc._dryoc import mac_hmac_sha256 as hmac_sha256
from dryoc._dryoc import mac_hmac_sha512 as hmac_sha512
from dryoc._dryoc import mac_hmac_sha512256 as hmac_sha512256
from dryoc._dryoc import mac_HmacSha256 as HmacSha256
from dryoc._dryoc import mac_HmacSha512 as HmacSha512
from dryoc._dryoc import mac_HmacSha512256 as HmacSha512256
from dryoc._dryoc import mac_poly1305 as poly1305
from dryoc._dryoc import mac_Poly1305 as Poly1305

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
