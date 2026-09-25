"""Argon2 password hashing."""

from __future__ import annotations

import pytest

from dryoc import CryptoError, InvalidInputError, pwhash

MIN = pwhash.Strength.MIN


@pytest.mark.parametrize("algorithm", list(pwhash.Algorithm))
def test_hash_and_verify(algorithm: pwhash.Algorithm) -> None:
    stored = pwhash.hash("correct horse", algorithm=algorithm, strength=MIN)
    prefix = "$argon2id$" if algorithm is pwhash.Algorithm.ARGON2ID13 else "$argon2i$"
    assert stored.startswith(prefix + "v=19$")
    pwhash.verify(stored, "correct horse")
    pwhash.verify(stored, b"correct horse")
    pwhash.verify(stored, bytearray(b"correct horse"))
    with pytest.raises(CryptoError):
        pwhash.verify(stored, "wrong horse")
    assert pwhash.hash("correct horse", algorithm=algorithm, strength=MIN) != stored


def test_hash_encodes_parameters() -> None:
    stored = pwhash.hash(b"pw", opslimit=3, memlimit=16 * 1024 * 1024)
    assert "$m=16384,t=3,p=1$" in stored
    pwhash.verify(stored, b"pw")


def test_str_passwords_are_utf8() -> None:
    stored = pwhash.hash("pässwörd", strength=MIN)
    pwhash.verify(stored, "pässwörd".encode())


def test_verify_rejects_malformed_hashes() -> None:
    with pytest.raises(InvalidInputError):
        pwhash.verify("not a hash", "pw")
    stored = pwhash.hash("pw", strength=MIN)
    with pytest.raises((InvalidInputError, CryptoError)):
        pwhash.verify(stored[:-3], "pw")


def test_presets_follow_libsodium() -> None:
    argon2id = pwhash.Algorithm.ARGON2ID13
    argon2i = pwhash.Algorithm.ARGON2I13
    assert pwhash.Strength.INTERACTIVE.limits(argon2id) == (2, 64 * 1024 * 1024)
    assert pwhash.Strength.MODERATE.limits(argon2id) == (3, 256 * 1024 * 1024)
    assert pwhash.Strength.SENSITIVE.limits(argon2id) == (4, 1024 * 1024 * 1024)
    assert pwhash.Strength.INTERACTIVE.limits(argon2i) == (4, 32 * 1024 * 1024)
    assert pwhash.Strength.MIN.limits(argon2i) == (3, 8192)


def test_derive_key_is_deterministic() -> None:
    salt = bytes(range(pwhash.SALT_SIZE))
    key = pwhash.derive_key("pw", salt, strength=MIN)
    assert len(key) == 32
    assert pwhash.derive_key(b"pw", bytearray(salt), strength=MIN) == key
    assert pwhash.derive_key("pW", salt, strength=MIN) != key
    assert len(pwhash.derive_key("pw", salt, length=pwhash.MIN_KEY_SIZE, strength=MIN)) == 16


def test_invalid_parameters() -> None:
    salt = bytes(pwhash.SALT_SIZE)
    with pytest.raises(InvalidInputError):
        pwhash.derive_key("pw", salt, length=pwhash.MIN_KEY_SIZE - 1, strength=MIN)
    with pytest.raises(InvalidInputError, match="salt length: expected exactly 16, got 8"):
        pwhash.derive_key("pw", salt[:8], strength=MIN)
    with pytest.raises(InvalidInputError):
        pwhash.hash("pw", opslimit=0, strength=MIN)
    with pytest.raises(InvalidInputError):
        pwhash.hash("pw", memlimit=1024, strength=MIN)
    with pytest.raises(ValueError):
        pwhash.hash("pw", algorithm=7, strength=MIN)  # type: ignore[arg-type]
