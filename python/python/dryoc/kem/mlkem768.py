"""ML-KEM-768 key encapsulation (FIPS 203).

The secret key is FIPS 203's 2400-byte expanded decapsulation key; seeds are
the 64-byte ``d || z`` key-generation seed. See :mod:`dryoc.kem` for an
example.
"""

from dryoc._dryoc import mlkem768_KeyPair as KeyPair
from dryoc._dryoc import mlkem768_PublicKey as PublicKey
from dryoc._dryoc import mlkem768_SecretKey as SecretKey

__all__ = ["KeyPair", "PublicKey", "SecretKey"]
