"""Key derivation: libsodium's BLAKE2b ``crypto_kdf`` and HKDF (RFC 5869).

Example::

    from dryoc import kdf

    master = kdf.Kdf.generate(context=b"MyApp v1")
    encryption_key = master.derive(1)
    signing_seed = master.derive(2)

    okm = kdf.hkdf_sha256(b"input keying material", salt=b"salt", info=b"purpose")
"""

from dryoc._dryoc import kdf_hkdf_sha256 as hkdf_sha256
from dryoc._dryoc import kdf_hkdf_sha512 as hkdf_sha512
from dryoc._dryoc import kdf_HkdfSha256 as HkdfSha256
from dryoc._dryoc import kdf_HkdfSha512 as HkdfSha512
from dryoc._dryoc import kdf_Kdf as Kdf

__all__ = ["HkdfSha256", "HkdfSha512", "Kdf", "hkdf_sha256", "hkdf_sha512"]
