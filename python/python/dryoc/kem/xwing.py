"""X-Wing hybrid key encapsulation (ML-KEM-768 + X25519).

The secret key is a 32-byte seed. See :mod:`dryoc.kem` for an example.
"""

from dryoc._dryoc import xwing_KeyPair as KeyPair
from dryoc._dryoc import xwing_PublicKey as PublicKey
from dryoc._dryoc import xwing_SecretKey as SecretKey

__all__ = ["KeyPair", "PublicKey", "SecretKey"]
