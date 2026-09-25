"""Behavior shared by all key objects: redacted reprs, constant-time
equality, hashing, explicit export, exceptions and buffer handling."""

import array
import hashlib
import pickle
import sys
import threading
from collections.abc import Callable
from typing import Any

import pytest

import dryoc
from dryoc import aead, box, kdf, kem, kx, secretbox, secretstream, sign
from dryoc import hash as dhash

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


WORDS = array.array("I", range(2048))


# One case per `util::Buf` extraction route; each must hash its raw bytes in C
# order. The large cases cross the 2 KiB threshold for detaching from the GIL.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"abcd", b"abcd"),
        (bytearray(b"abcd"), b"abcd"),
        (memoryview(bytearray(b"abcd")).toreadonly(), b"abcd"),
        (memoryview(b"a-b-c-d")[::2], b"abcd"),
        (memoryview(b"dcba")[::-1], b"abcd"),
        (array.array("I", [1, 2, 3, 4]), array.array("I", [1, 2, 3, 4]).tobytes()),
        (memoryview(b"abcdefgh").cast("I"), b"abcdefgh"),
        (memoryview(bytes(range(24))).cast("I", (2, 3)), bytes(range(24))),
        (WORDS, WORDS.tobytes()),
        (memoryview(array.array("I", [1, 2, 3, 4]))[::2], array.array("I", [1, 3]).tobytes()),
        (memoryview(bytes(range(8))).cast("H")[::-2], bytes([6, 7, 2, 3])),
        (memoryview(WORDS)[::2], WORDS[::2].tobytes()),
    ],
    ids=[
        "bytes",
        "bytearray",
        "readonly-memoryview",
        "strided-bytes",
        "reversed-bytes",
        "array-I",
        "cast-I",
        "cast-I-2d",
        "large-array-I",
        "strided-array-I",
        "reversed-cast-H",
        "large-strided-array-I",
    ],
)
def test_buffers_are_read_as_raw_bytes_in_c_order(value: Any, expected: bytes) -> None:
    assert dhash.sha256(value) == hashlib.sha256(expected).digest()


class ReExported(bytearray):
    def __buffer__(self, flags: int) -> memoryview:
        return memoryview(b"exported")


@pytest.mark.skipif(sys.version_info < (3, 12), reason="__buffer__ overrides need PEP 688 (3.12)")
def test_bytearray_subclass_is_read_through_its_buffer() -> None:
    # The locked `bytearray` copy reads the object's storage, so it must not
    # be used for subclasses, whose exported bytes can differ.
    value = ReExported(b"storage")
    assert dhash.sha256(value) == hashlib.sha256(b"exported").digest()


@pytest.mark.skipif(
    getattr(sys, "_is_gil_enabled", lambda: True)(),
    reason="concurrent bytearray writes only race the copy with the GIL disabled "
    "(free-threaded build, e.g. 3.14t)",
)
def test_bytearray_input_is_copied_atomically_under_concurrent_writes() -> None:
    size = 16 << 20
    old, new = bytes(size), b"\xff" * size
    expected = {hashlib.sha256(old).digest(), hashlib.sha256(new).digest()}
    shared = bytearray(old)
    running, stop = threading.Event(), threading.Event()

    def writer() -> None:
        running.set()
        while not stop.is_set():
            # Same-length assignments never resize. The reversed extended
            # slice writes back to front, so an unlocked front-to-back copy
            # running concurrently crosses the write front and sees both
            # values.
            shared[::-1] = new
            shared[::-1] = old

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        running.wait()
        digests = [dhash.sha256(shared) for _ in range(30)]
    finally:
        stop.set()
        thread.join()
    torn = sum(digest not in expected for digest in digests)
    assert torn == 0, f"{torn} of {len(digests)} digests saw a partially written bytearray"


def test_random_bytes() -> None:
    assert len(dryoc.random_bytes(0)) == 0
    first, second = dryoc.random_bytes(64), dryoc.random_bytes(64)
    assert len(first) == 64
    assert first != second
    assert len(dryoc.random_bytes(1 << 20)) == 1 << 20
    with pytest.raises(OverflowError):
        dryoc.random_bytes(-1)
