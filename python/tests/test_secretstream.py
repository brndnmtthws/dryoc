"""Encrypted streams."""

from __future__ import annotations

import pytest
from conftest import flip

from dryoc import CryptoError, DryocError, InvalidInputError
from dryoc.secretstream import Decryptor, Encryptor, Key, Tag


def encrypt(key: Key, messages: list[tuple[bytes, Tag]]) -> tuple[bytes, list[bytes]]:
    encryptor = Encryptor(key)
    return encryptor.header, [encryptor.push(m, tag=t) for m, t in messages]


def test_roundtrip_with_tags_and_associated_data() -> None:
    key = Key.generate()
    with Encryptor(key) as encryptor:
        header = encryptor.header
        chunks = [
            encryptor.push(b"one"),
            encryptor.push(bytearray(b"two"), tag=Tag.PUSH, associated_data=b"ad"),
            encryptor.push(memoryview(b"three"), tag=Tag.FINAL),
        ]
        assert encryptor.finished
    assert len(header) == Encryptor.HEADER_SIZE
    assert len(chunks[0]) == 3 + Encryptor.OVERHEAD
    with Decryptor(key, header) as decryptor:
        assert decryptor.pull(chunks[0]) == (b"one", Tag.MESSAGE)
        message, tag = decryptor.pull(chunks[1], associated_data=b"ad")
        assert (message, tag) == (b"two", Tag.PUSH)
        assert isinstance(tag, Tag)
        assert decryptor.pull(chunks[2]) == (b"three", Tag.FINAL)
        assert decryptor.finished


def test_rekey_must_match_on_both_sides() -> None:
    key = Key.generate()
    encryptor = Encryptor(key)
    first = encryptor.push(b"a")
    encryptor.rekey()
    second = encryptor.push(b"b", tag=Tag.FINAL)
    decryptor = Decryptor(key, encryptor.header)
    assert decryptor.pull(first)[0] == b"a"
    decryptor.rekey()
    assert decryptor.pull(second) == (b"b", Tag.FINAL)

    unsynced = Decryptor(key, encryptor.header)
    unsynced.pull(first)
    with pytest.raises(CryptoError):
        unsynced.pull(second)


def test_rekey_tag_rekeys_automatically() -> None:
    key = Key.generate()
    header, chunks = encrypt(key, [(b"a", Tag.REKEY), (b"b", Tag.FINAL)])
    decryptor = Decryptor(key, header)
    assert [decryptor.pull(c) for c in chunks] == [(b"a", Tag.REKEY), (b"b", Tag.FINAL)]


@pytest.mark.parametrize(
    "mangle",
    [
        pytest.param(lambda c: [c[1], c[0], c[2]], id="reordered"),
        pytest.param(lambda c: [c[0], c[0], c[1], c[2]], id="duplicated"),
        pytest.param(lambda c: [c[0], c[2]], id="dropped"),
        pytest.param(lambda c: [c[0], flip(c[1], 0), c[2]], id="modified-tag-byte"),
        pytest.param(lambda c: [c[0], flip(c[1], -1), c[2]], id="modified-mac"),
    ],
)
def test_stream_manipulation_raises(mangle) -> None:  # type: ignore[no-untyped-def]
    key = Key.generate()
    header, chunks = encrypt(key, [(b"a", Tag.MESSAGE), (b"b", Tag.MESSAGE), (b"c", Tag.FINAL)])
    decryptor = Decryptor(key, header)
    with pytest.raises(CryptoError):
        for chunk in mangle(chunks):
            decryptor.pull(chunk)


def test_failed_pull_leaves_state_usable() -> None:
    key = Key.generate()
    header, chunks = encrypt(key, [(b"a", Tag.MESSAGE), (b"b", Tag.FINAL)])
    decryptor = Decryptor(key, header)
    with pytest.raises(CryptoError):
        decryptor.pull(flip(chunks[0], 5))
    assert decryptor.pull(chunks[0]) == (b"a", Tag.MESSAGE)


def test_wrong_key_or_header_raises() -> None:
    key = Key.generate()
    header, chunks = encrypt(key, [(b"a", Tag.FINAL)])
    with pytest.raises(CryptoError):
        Decryptor(Key.generate(), header).pull(chunks[0])
    with pytest.raises(CryptoError):
        Decryptor(key, flip(header, 0)).pull(chunks[0])
    with pytest.raises(InvalidInputError, match="header must be exactly 24"):
        Decryptor(key, header[:-1])
    with pytest.raises(InvalidInputError):
        Decryptor(key, header).pull(b"short")


def test_data_after_final_is_rejected() -> None:
    key = Key.generate()
    encryptor = Encryptor(key)
    final = encryptor.push(b"end", tag=Tag.FINAL)
    with pytest.raises(DryocError, match="finished"):
        encryptor.push(b"more")
    decryptor = Decryptor(key, encryptor.header)
    decryptor.pull(final)
    with pytest.raises(CryptoError, match="after the Tag.FINAL"):
        decryptor.pull(final)


def test_truncated_stream_detected_by_context_manager() -> None:
    key = Key.generate()
    header, chunks = encrypt(key, [(b"a", Tag.MESSAGE), (b"b", Tag.FINAL)])
    with pytest.raises(CryptoError, match="truncated"):
        with Decryptor(key, header) as decryptor:
            decryptor.pull(chunks[0])
    # The state was wiped on exit.
    with pytest.raises(DryocError, match="closed"):
        decryptor.pull(chunks[1])


def test_encryptor_context_manager_requires_final() -> None:
    with pytest.raises(DryocError, match="without a Tag.FINAL"):
        with Encryptor(Key.generate()) as encryptor:
            encryptor.push(b"a")
    with pytest.raises(DryocError, match="closed"):
        encryptor.push(b"b")


def test_context_managers_do_not_mask_exceptions() -> None:
    with pytest.raises(KeyError):
        with Encryptor(Key.generate()):
            raise KeyError("boom")
    with pytest.raises(KeyError):
        with Decryptor(Key.generate(), bytes(24)):
            raise KeyError("boom")


def test_invalid_tag_raises_without_advancing_the_stream() -> None:
    key = Key.generate()
    encryptor = Encryptor(key)
    with pytest.raises(InvalidInputError, match="invalid secretstream tag"):
        encryptor.push(b"x", tag=0x80)
    chunk = encryptor.push(b"y", tag=Tag.FINAL)
    assert Decryptor(key, encryptor.header).pull(chunk) == (b"y", Tag.FINAL)


def test_tag_enum_values_match_libsodium() -> None:
    assert (Tag.MESSAGE, Tag.PUSH, Tag.REKEY, Tag.FINAL) == (0, 1, 2, 3)
    assert Tag.FINAL == Tag.PUSH | Tag.REKEY


def test_close_inside_context_does_not_hide_truncation() -> None:
    key = Key.generate()
    header, chunks = encrypt(key, [(b"a", Tag.MESSAGE), (b"b", Tag.FINAL)])
    with pytest.raises(CryptoError, match="truncated"):
        with Decryptor(key, header) as decryptor:
            decryptor.pull(chunks[0])
            decryptor.close()
    with pytest.raises(DryocError, match="without a Tag.FINAL"):
        with Encryptor(key) as encryptor:
            encryptor.push(b"a")
            encryptor.close()


def test_close_after_final_inside_context_is_accepted() -> None:
    key = Key.generate()
    with Encryptor(key) as encryptor:
        header = encryptor.header
        final = encryptor.push(b"end", tag=Tag.FINAL)
        encryptor.close()
    with Decryptor(key, header) as decryptor:
        decryptor.pull(final)
        decryptor.close()


def test_explicit_close_outside_context_never_raises() -> None:
    key = Key.generate()
    encryptor = Encryptor(key)
    encryptor.push(b"a")
    encryptor.close()
    encryptor.close()
    assert not encryptor.finished
    decryptor = Decryptor(key, encryptor.header)
    decryptor.close()
    assert not decryptor.finished
    with pytest.raises(DryocError, match="closed"):
        decryptor.pull(b"x" * 32)
