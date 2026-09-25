"""Argon2 password hashing, compatible with libsodium's ``crypto_pwhash``.

Store passwords with :func:`hash` and check them with :func:`verify`; the
encoded string (``$argon2id$v=19$m=...,t=...,p=1$salt$hash``) carries its own
salt and parameters, so it is all you need to store. Derive encryption keys
from passphrases with :func:`derive_key`.

Passwords may be ``str`` (encoded as UTF-8) or any bytes-like object. All
functions release the GIL while hashing.

Example::

    import dryoc
    from dryoc import pwhash

    stored = pwhash.hash("correct horse battery staple")
    pwhash.verify(stored, "correct horse battery staple")  # raises CryptoError if wrong

    salt = dryoc.random_bytes(pwhash.SALT_SIZE)
    key = pwhash.derive_key("passphrase", salt, strength=pwhash.Strength.MODERATE)
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from dryoc import _dryoc

if TYPE_CHECKING:
    from typing_extensions import Buffer

__all__ = [
    "MAX_KEY_SIZE",
    "MIN_KEY_SIZE",
    "SALT_SIZE",
    "Algorithm",
    "Strength",
    "derive_key",
    "hash",
    "verify",
]

_CONSTANTS = _dryoc.pwhash_constants

SALT_SIZE: int = _CONSTANTS["SALT_SIZE"]
"""Length of the salt :func:`derive_key` expects, in bytes."""
MIN_KEY_SIZE: int = _CONSTANTS["MIN_KEY_SIZE"]
"""Shortest key :func:`derive_key` produces, in bytes."""
MAX_KEY_SIZE: int = _CONSTANTS["MAX_KEY_SIZE"]
"""Longest key :func:`derive_key` produces, in bytes."""


class Algorithm(enum.IntEnum):
    """Argon2 variants, numbered as libsodium's ``crypto_pwhash_ALG_*``."""

    ARGON2I13 = 1
    """Argon2i version 1.3."""
    ARGON2ID13 = 2
    """Argon2id version 1.3, the recommended default."""


class Strength(enum.Enum):
    """libsodium's work-factor presets.

    ``INTERACTIVE`` suits online logins, ``MODERATE`` more sensitive
    operations, and ``SENSITIVE`` rarely derived, high-value keys (it uses 1 GiB
    of memory with Argon2id). ``MIN`` is the smallest allowed setting and is
    only suitable for tests.
    """

    MIN = "min"
    INTERACTIVE = "interactive"
    MODERATE = "moderate"
    SENSITIVE = "sensitive"

    def limits(self, algorithm: Algorithm = Algorithm.ARGON2ID13) -> tuple[int, int]:
        """Returns ``(opslimit, memlimit)`` for this preset and ``algorithm``.

        ``memlimit`` is in bytes.
        """
        opslimit, memlimit = _CONSTANTS["LIMITS"][(int(Algorithm(algorithm)), self.value)]
        return opslimit, memlimit


def _limits(
    strength: Strength, opslimit: int | None, memlimit: int | None, algorithm: Algorithm
) -> tuple[int, int, int]:
    algorithm = Algorithm(algorithm)
    preset_ops, preset_mem = Strength(strength).limits(algorithm)
    return (
        preset_ops if opslimit is None else opslimit,
        preset_mem if memlimit is None else memlimit,
        int(algorithm),
    )


def hash(
    password: str | Buffer,
    *,
    strength: Strength = Strength.INTERACTIVE,
    opslimit: int | None = None,
    memlimit: int | None = None,
    algorithm: Algorithm = Algorithm.ARGON2ID13,
) -> str:
    """Hashes ``password`` with a random salt for storage.

    Returns libsodium's encoded string (``crypto_pwhash_str`` format).
    ``strength`` picks the work factor; ``opslimit`` (passes) and
    ``memlimit`` (bytes) override the preset individually.

    Raises :class:`~dryoc.InvalidInputError` if a parameter is out of range.
    """
    ops, mem, alg = _limits(strength, opslimit, memlimit, algorithm)
    return _dryoc.pwhash_hash_password(password, ops, mem, alg)


def verify(password_hash: str, password: str | Buffer) -> None:
    """Checks ``password`` against an encoded hash from :func:`hash` (or
    libsodium's ``crypto_pwhash_str``).

    Returns ``None`` on success. Raises :class:`~dryoc.CryptoError` if the
    password is wrong and :class:`~dryoc.InvalidInputError` if
    ``password_hash`` is malformed.
    """
    _dryoc.pwhash_verify_password(password_hash, password)


def derive_key(
    password: str | Buffer,
    salt: Buffer,
    *,
    length: int = 32,
    strength: Strength = Strength.INTERACTIVE,
    opslimit: int | None = None,
    memlimit: int | None = None,
    algorithm: Algorithm = Algorithm.ARGON2ID13,
) -> bytes:
    """Derives ``length`` bytes of key material from ``password`` and ``salt``
    (libsodium's ``crypto_pwhash``).

    The same password, salt and parameters always give the same key, so store
    the salt (:data:`SALT_SIZE` random bytes) and parameters with the data.

    Raises :class:`~dryoc.InvalidInputError` if a parameter is out of range.
    """
    ops, mem, alg = _limits(strength, opslimit, memlimit, algorithm)
    return _dryoc.pwhash_derive_key(password, salt, length, ops, mem, alg)
