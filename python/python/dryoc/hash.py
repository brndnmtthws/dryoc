"""Hash functions with the :mod:`hashlib` interface.

Classes (``Sha256``, ``Blake2b``, ``Shake128``, ...) are incremental hashers
with ``update()``, ``digest()``, ``hexdigest()``, ``copy()``, ``name``,
``digest_size`` and ``block_size``. The lowercase functions are one-shot and
return ``bytes``.

BLAKE2b follows libsodium's ``crypto_generichash``: its default digest size is
32 bytes (``hashlib.blake2b`` defaults to 64).

Example::

    from dryoc import hash

    assert hash.sha256(b"abc") == hash.Sha256(b"abc").digest()
    h = hash.Blake2b(digest_size=32)
    h.update(b"streamed ")
    h.update(b"input")
    print(h.hexdigest())
"""

from dryoc._dryoc import hash_Blake2b as Blake2b
from dryoc._dryoc import hash_blake2b as blake2b
from dryoc._dryoc import hash_Sha3_256 as Sha3_256
from dryoc._dryoc import hash_sha3_256 as sha3_256
from dryoc._dryoc import hash_Sha3_512 as Sha3_512
from dryoc._dryoc import hash_sha3_512 as sha3_512
from dryoc._dryoc import hash_Sha256 as Sha256
from dryoc._dryoc import hash_sha256 as sha256
from dryoc._dryoc import hash_Sha512 as Sha512
from dryoc._dryoc import hash_sha512 as sha512
from dryoc._dryoc import hash_Shake128 as Shake128
from dryoc._dryoc import hash_shake128 as shake128
from dryoc._dryoc import hash_Shake128Reader as Shake128Reader
from dryoc._dryoc import hash_Shake256 as Shake256
from dryoc._dryoc import hash_shake256 as shake256
from dryoc._dryoc import hash_Shake256Reader as Shake256Reader
from dryoc._dryoc import hash_TurboShake128 as TurboShake128
from dryoc._dryoc import hash_turboshake128 as turboshake128
from dryoc._dryoc import hash_TurboShake128Reader as TurboShake128Reader
from dryoc._dryoc import hash_TurboShake256 as TurboShake256
from dryoc._dryoc import hash_turboshake256 as turboshake256
from dryoc._dryoc import hash_TurboShake256Reader as TurboShake256Reader

__all__ = [
    "Blake2b",
    "Sha3_256",
    "Sha3_512",
    "Sha256",
    "Sha512",
    "Shake128",
    "Shake128Reader",
    "Shake256",
    "Shake256Reader",
    "TurboShake128",
    "TurboShake128Reader",
    "TurboShake256",
    "TurboShake256Reader",
    "blake2b",
    "sha3_256",
    "sha3_512",
    "sha256",
    "sha512",
    "shake128",
    "shake256",
    "turboshake128",
    "turboshake256",
]
