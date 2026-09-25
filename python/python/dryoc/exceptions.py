"""Exceptions raised by dryoc.

Every exception dryoc raises on purpose derives from :class:`DryocError`.
"""

__all__ = ["CryptoError", "DryocError", "InvalidInputError"]


class DryocError(Exception):
    """Base class for all dryoc errors."""


class CryptoError(DryocError):
    """Authentication, decryption, or signature verification failed.

    Raised when a ciphertext, tag, signature, or password does not verify:
    the data was modified, or the wrong key, nonce, or associated data was
    used. Never ignore it.
    """


class InvalidInputError(DryocError, ValueError):
    """An argument was malformed: wrong length, out-of-range value, bad
    encoding, or an unusable key. Also a :class:`ValueError`."""
