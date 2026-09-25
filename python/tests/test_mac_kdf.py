"""MACs and key derivation."""

import hashlib
import hmac

import pytest
from conftest import BUFFER_TYPES, flip

from dryoc import CryptoError, DryocError, InvalidInputError, kdf, mac

KEY = bytes(range(32))


def stdlib_hmac(algorithm: str, key: bytes, data: bytes, truncate: int | None = None) -> bytes:
    return hmac.new(key, data, algorithm).digest()[:truncate]


MACS = [
    (mac.HmacSha256, mac.hmac_sha256, lambda k, d: stdlib_hmac("sha256", k, d)),
    (mac.HmacSha512, mac.hmac_sha512, lambda k, d: stdlib_hmac("sha512", k, d)),
    (mac.HmacSha512256, mac.hmac_sha512256, lambda k, d: stdlib_hmac("sha512", k, d, 32)),
]


@pytest.mark.parametrize(("cls", "oneshot", "oracle"), MACS)
def test_hmac_matches_stdlib(cls, oneshot, oracle) -> None:  # type: ignore[no-untyped-def]
    for data in (b"", b"message", bytes(5000)):
        expected = oracle(KEY, data)
        assert oneshot(KEY, data) == expected
        assert cls(KEY, data).digest() == expected
        assert len(expected) == cls.digest_size


# RFC 8439 section 2.5.2.
POLY1305_KEY = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
POLY1305_TAG = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")


def test_poly1305_rfc8439() -> None:
    message = b"Cryptographic Forum Research Group"
    assert mac.poly1305(POLY1305_KEY, message) == POLY1305_TAG
    authenticator = mac.Poly1305(POLY1305_KEY)
    authenticator.update(message[:10])
    authenticator.update(message[10:])
    authenticator.verify(POLY1305_TAG)


@pytest.mark.parametrize("cls", [m[0] for m in MACS] + [mac.Poly1305])
def test_mac_lifecycle(cls) -> None:  # type: ignore[no-untyped-def]
    key = cls.generate_key()
    assert len(key) == cls.KEY_SIZE
    authenticator = cls(key)
    authenticator.update(b"part one ")
    authenticator.update(bytearray(b"part two"))
    tag = authenticator.digest()
    assert authenticator.digest() == tag
    assert authenticator.hexdigest() == tag.hex()
    authenticator.verify(tag)
    with pytest.raises(CryptoError):
        authenticator.verify(flip(tag, 0))
    with pytest.raises(CryptoError):
        authenticator.verify(tag[:-1])
    with pytest.raises(DryocError, match="already finalized"):
        authenticator.update(b"more")
    with pytest.raises(CryptoError):
        cls(key, b"part one part tw0").verify(tag)


@pytest.mark.parametrize("make", BUFFER_TYPES)
def test_mac_bytes_like(make) -> None:  # type: ignore[no-untyped-def]
    assert mac.hmac_sha256(make(KEY), make(b"data")) == stdlib_hmac("sha256", KEY, b"data")


def test_mac_key_length() -> None:
    with pytest.raises(InvalidInputError, match="key must be exactly 32"):
        mac.HmacSha256(bytes(20))
    with pytest.raises(InvalidInputError):
        mac.poly1305(bytes(16), b"")


# libsodium test/default/kdf.c key and context, via dryoc's Rust tests.
KDF_KAT = {
    0: (
        "e9136a52b9690eb4df4e9665e819a6d3",
        "c13fcc2e6cd0cd0f82d93b163a5696c5105378f8c629d36baf3ae0239de9c280",
        "a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d807"
        "1b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614",
    ),
    2**64 - 1: (
        "040f6b7312b53bce5d711bb9c589cdd4",
        "500c3043b2b9177ec843ecbe9f98f92d8c11fbbd10a225ab844548de89c21d55",
        "6be4464350f6934d151c1bb8f555bc18e75028be95b892c6dca047101f2827a1"
        "950b2b0fb35e996a2782db9a760e76c8b8da52e362f741bf5bcfefff0fc943fc",
    ),
}


def test_kdf_libsodium_known_answers() -> None:
    master = kdf.Kdf(bytes(range(32)), b"KDF test")
    for subkey_id, expected in KDF_KAT.items():
        for length, value in zip((16, 32, 64), expected, strict=True):
            assert master.derive(subkey_id, length) == bytes.fromhex(value)
    assert master.derive(0) == bytes.fromhex(KDF_KAT[0][1])
    assert master.context == b"KDF test"


def test_kdf_bounds() -> None:
    master = kdf.Kdf.generate(b"MyApp v1")
    assert master.derive(1) != master.derive(2)
    assert kdf.Kdf(bytes(master), master.context) == master
    with pytest.raises(InvalidInputError):
        master.derive(1, 15)
    with pytest.raises(InvalidInputError):
        master.derive(1, 65)
    with pytest.raises(OverflowError):
        master.derive(-1)
    with pytest.raises(InvalidInputError, match="context must be exactly 8"):
        kdf.Kdf.generate(b"short")


def python_hkdf(algorithm: str, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    size = hashlib.new(algorithm).digest_size
    prk = hmac.new(salt or bytes(size), ikm, algorithm).digest()
    okm, block = b"", b""
    for counter in range(1, -(-length // size) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), algorithm).digest()
        okm += block
    return okm[:length]


def test_hkdf_sha256_rfc5869_case_1() -> None:
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(13))
    info = bytes(range(0xF0, 0xFA))
    okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert kdf.hkdf_sha256(ikm, salt=salt, info=info, length=42) == okm
    prk = kdf.HkdfSha256.extract(ikm, salt=salt)
    assert bytes(prk) == bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    assert prk.expand(info, 42) == okm
    assert kdf.HkdfSha256(bytes(prk)).expand(info=info, length=42) == okm


@pytest.mark.parametrize(
    ("oneshot", "cls", "algorithm"),
    [(kdf.hkdf_sha256, kdf.HkdfSha256, "sha256"), (kdf.hkdf_sha512, kdf.HkdfSha512, "sha512")],
)
def test_hkdf_matches_reference(oneshot, cls, algorithm) -> None:  # type: ignore[no-untyped-def]
    for salt in (b"", b"salt"):
        for length in (0, 1, 32, 100, cls.MAX_OUTPUT_SIZE):
            expected = python_hkdf(algorithm, b"ikm", salt, b"info", length)
            assert oneshot(b"ikm", salt=salt or None, info=b"info", length=length) == expected
    with pytest.raises(InvalidInputError):
        oneshot(b"ikm", length=cls.MAX_OUTPUT_SIZE + 1)
    assert oneshot(b"ikm") == python_hkdf(algorithm, b"ikm", b"", b"", 32)
