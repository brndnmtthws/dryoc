"""Behavior shared by all key objects: redacted reprs, constant-time
equality, hashing, explicit export, exceptions and buffer handling."""

from __future__ import annotations

import pickle
from collections.abc import Callable
from typing import Any

import pytest

import dryoc
from dryoc import aead, box, kdf, kem, kx, secretbox, secretstream, sign

SECRETS: list[tuple[str, Callable[[], Any]]] = [
    ("secretbox.SecretBox", secretbox.SecretBox.generate),
    ("aead.XChaCha20Poly1305", aead.XChaCha20Poly1305.generate),
    ("aead.ChaCha20Poly1305", aead.ChaCha20Poly1305.generate),
    ("box.SecretKey", box.SecretKey.generate),
    ("box.KeyPair", box.KeyPair.generate),
    ("secretstream.Key", secretstream.Key.generate),
    ("sign.SigningKey", sign.SigningKey.generate),
    ("kdf.Kdf", lambda: kdf.Kdf.generate(b"context!")),
    ("kdf.HkdfSha256", kdf.HkdfSha256.generate),
    ("kdf.HkdfSha512", kdf.HkdfSha512.generate),
    ("kem.xwing.KeyPair", kem.xwing.KeyPair.generate),
    ("kem.xwing.SecretKey", lambda: kem.xwing.KeyPair.generate().secret_key),
    ("kem.mlkem768.KeyPair", kem.mlkem768.KeyPair.generate),
    ("kem.mlkem768.SecretKey", lambda: kem.mlkem768.KeyPair.generate().secret_key),
    (
        "kx.SessionKeys",
        lambda: kx.client_session_keys(box.KeyPair.generate(), box.KeyPair.generate().public_key),
    ),
]

PUBLICS: list[tuple[str, Callable[[], Any]]] = [
    ("box.PublicKey", lambda: box.KeyPair.generate().public_key),
    ("sign.VerifyKey", lambda: sign.SigningKey.generate().verify_key),
    ("kem.xwing.PublicKey", lambda: kem.xwing.KeyPair.generate().public_key),
    ("kem.mlkem768.PublicKey", lambda: kem.mlkem768.KeyPair.generate().public_key),
]


def secret_bytes(obj: Any) -> bytes:
    if isinstance(obj, (box.KeyPair, kem.xwing.KeyPair, kem.mlkem768.KeyPair)):
        return bytes(obj.secret_key)
    if isinstance(obj, kx.SessionKeys):
        return obj.rx + obj.tx
    return bytes(obj)


@pytest.mark.parametrize(("name", "make"), SECRETS, ids=[s[0] for s in SECRETS])
def test_secret_objects(name: str, make: Callable[[], Any]) -> None:
    key = make()
    raw = secret_bytes(key)
    text = repr(key)
    assert "redacted" in text
    assert raw.hex() not in text
    assert raw.hex()[:16] not in text
    assert repr(raw) not in text
    assert str(key) == text
    with pytest.raises(TypeError, match="unhashable"):
        hash(key)
    with pytest.raises(TypeError):
        pickle.dumps(key)
    assert key == key
    assert key != make()
    assert key != raw
    assert type(key).__module__ == "dryoc." + name.rsplit(".", 1)[0]


@pytest.mark.parametrize(("name", "make"), PUBLICS, ids=[p[0] for p in PUBLICS])
def test_public_keys(name: str, make: Callable[[], Any]) -> None:
    key = make()
    clone = type(key)(bytes(key))
    assert clone == key
    assert hash(clone) == hash(key)
    assert len({key, clone, make()}) == 2
    assert bytes(key).hex()[:32] in repr(key)
    assert type(key).from_bytes(memoryview(bytes(key))) == key
    assert len(bytes(key)) == type(key).SIZE


def test_secret_round_trip_through_bytes() -> None:
    key = secretbox.SecretBox.generate()
    assert secretbox.SecretBox(bytes(key)) == key
    assert secretbox.SecretBox.from_bytes(bytearray(bytes(key))) == key
    pair = box.KeyPair.generate()
    assert box.KeyPair.from_secret_key(bytes(pair.secret_key)) == pair


def test_exception_hierarchy() -> None:
    assert issubclass(dryoc.CryptoError, dryoc.DryocError)
    assert issubclass(dryoc.InvalidInputError, dryoc.DryocError)
    assert issubclass(dryoc.InvalidInputError, ValueError)
    assert not issubclass(dryoc.CryptoError, ValueError)
    assert dryoc.exceptions.CryptoError is dryoc.CryptoError


@pytest.mark.parametrize(
    "value", ["text", 42, [1, 2, 3], None, object()], ids=["str", "int", "list", "None", "object"]
)
def test_non_bytes_like_inputs_raise_type_error(value: object) -> None:
    key = secretbox.SecretBox.generate()
    with pytest.raises(TypeError, match="bytes-like"):
        key.encrypt(value)  # type: ignore[arg-type]


def test_non_contiguous_and_typed_buffers_are_accepted() -> None:
    import array

    key = secretbox.SecretBox.generate()
    words = array.array("I", [1, 2, 3, 4])
    assert key.decrypt(*key.encrypt(words)) == words.tobytes()
    strided = memoryview(b"a-b-c-d")[::2]
    assert key.decrypt(*key.encrypt(strided)) == b"abcd"


def test_random_bytes() -> None:
    assert len(dryoc.random_bytes(0)) == 0
    first, second = dryoc.random_bytes(64), dryoc.random_bytes(64)
    assert len(first) == 64
    assert first != second
    assert len(dryoc.random_bytes(1 << 20)) == 1 << 20
    with pytest.raises(OverflowError):
        dryoc.random_bytes(-1)
