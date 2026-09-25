"""Hashes: known answers against hashlib (OpenSSL) and RFC 9861, and the
hashlib protocol."""

import hashlib

import pytest

from dryoc import InvalidInputError
from dryoc import hash as dhash

MESSAGES = [b"", b"abc", bytes(i * 31 % 251 for i in range(1000))]

FIXED = [
    (dhash.Sha256, dhash.sha256, "sha256", 32, 64),
    (dhash.Sha512, dhash.sha512, "sha512", 64, 128),
    (dhash.Sha3_256, dhash.sha3_256, "sha3_256", 32, 136),
    (dhash.Sha3_512, dhash.sha3_512, "sha3_512", 64, 72),
]


@pytest.mark.parametrize(("cls", "oneshot", "name", "digest_size", "block_size"), FIXED)
def test_fixed_hashes_match_hashlib(cls, oneshot, name, digest_size, block_size) -> None:  # type: ignore[no-untyped-def]
    assert (cls.name, cls.digest_size, cls.block_size) == (name, digest_size, block_size)
    for message in MESSAGES:
        expected = hashlib.new(name, message)
        assert oneshot(message) == expected.digest()
        h = cls(message)
        assert h.digest() == expected.digest()
        assert h.hexdigest() == expected.hexdigest()


@pytest.mark.parametrize(("cls", "oneshot", "name", "digest_size", "block_size"), FIXED)
def test_hashlib_protocol(cls, oneshot, name, digest_size, block_size) -> None:  # type: ignore[no-untyped-def]
    h = cls()
    for chunk in (b"a", bytearray(b"b" * 200), memoryview(b"c" * 5000)):
        h.update(chunk)
    data = b"a" + b"b" * 200 + b"c" * 5000
    first = h.digest()
    assert h.digest() == first == oneshot(data)
    clone = h.copy()
    clone.update(b"tail")
    assert h.digest() == first
    assert clone.digest() == hashlib.new(name, data + b"tail").digest()


def test_blake2b_matches_hashlib_and_libsodium_defaults() -> None:
    assert dhash.Blake2b().digest_size == 32
    assert (dhash.Blake2b.name, dhash.Blake2b.block_size) == ("blake2b", 128)
    for message in MESSAGES:
        for size in (1, 16, 32, 64):
            expected = hashlib.blake2b(message, digest_size=size).digest()
            assert dhash.blake2b(message, digest_size=size) == expected
            assert dhash.Blake2b(message, digest_size=size).digest() == expected
        for key in (bytes(range(16)), bytes(range(32)), bytes(range(64))):
            expected = hashlib.blake2b(message, key=key, digest_size=32).digest()
            assert dhash.blake2b(message, key=key) == expected
            assert dhash.Blake2b(message, key=bytearray(key)).hexdigest() == expected.hex()
    # An empty key is the same as no key, as in libsodium.
    assert dhash.blake2b(b"abc", key=b"") == dhash.blake2b(b"abc")


def test_blake2b_copy_is_independent() -> None:
    h = dhash.Blake2b(b"prefix ", key=b"k" * 32, digest_size=48)
    clone = h.copy()
    h.update(b"one")
    clone.update(b"two")
    assert h.digest() == hashlib.blake2b(b"prefix one", key=b"k" * 32, digest_size=48).digest()
    assert clone.digest() == hashlib.blake2b(b"prefix two", key=b"k" * 32, digest_size=48).digest()
    assert clone.digest_size == 48


@pytest.mark.parametrize("size", [0, 65])
def test_blake2b_digest_size_bounds(size: int) -> None:
    with pytest.raises(InvalidInputError, match="digest_size"):
        dhash.Blake2b(digest_size=size)
    with pytest.raises(InvalidInputError, match="digest_size"):
        dhash.blake2b(b"", digest_size=size)


def test_blake2b_key_too_long() -> None:
    with pytest.raises(InvalidInputError, match="at most 64"):
        dhash.blake2b(b"", key=bytes(65))


@pytest.mark.parametrize(
    ("cls", "oneshot", "reference", "rate"),
    [
        (dhash.Shake128, dhash.shake128, hashlib.shake_128, 168),
        (dhash.Shake256, dhash.shake256, hashlib.shake_256, 136),
    ],
)
def test_shake_matches_hashlib(cls, oneshot, reference, rate) -> None:  # type: ignore[no-untyped-def]
    assert (cls.name, cls.digest_size, cls.block_size) == (reference().name, 0, rate)
    for message in MESSAGES:
        expected = reference(message)
        assert oneshot(message, 100) == expected.digest(100)
        h = cls(message)
        assert h.digest(200) == expected.digest(200)
        assert h.hexdigest(7) == expected.hexdigest(7)
        assert h.digest(0) == b""
        reader = h.reader()
        assert reader.read(10) + reader.read(0) + reader.read(190) == expected.digest(200)


def ptn(length: int) -> bytes:
    """RFC 9861's ptn(n): the repeating 0x00..0xFA pattern."""
    return bytes(i % 251 for i in range(length))


def unhex(spaced: str) -> bytes:
    return bytes.fromhex(spaced.replace(" ", ""))


# RFC 9861 section 5 (as vendored in dryoc's Rust tests).
TURBOSHAKE128 = [
    (b"", 0x1F, 64, "1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C3E8CCAE2A4DAE56C84A04C2385C03C15E8193BDF58737363321691C05462C8DF"),
    (ptn(1), 0x1F, 32, "55CEDD6F60AF7BB29A4042AE832EF3F58DB7299F893EBB9247247D856958DAA9"),
    (ptn(17), 0x1F, 32, "9C97D036A3BAC819DB70EDE0CA554EC6E4C2A1A4FFBFD9EC269CA6A111161233"),
    (ptn(17**2), 0x1F, 32, "96C77C279E0126F7FC07C9B07F5CDAE1E0BE60BDBE10620040E75D7223A624D2"),
    (b"\xff" * 3, 0x01, 32, "BF323F940494E88EE1C540FE660BE8A0C93F43D15EC006998462FA994EED5DAB"),
    (b"\xff", 0x06, 32, "8EC9C66465ED0D4A6C35D13506718D687A25CB05C74CCA1E42501ABD83874A67"),
    (b"\xff" * 3, 0x07, 32, "B658576001CAD9B1E5F399A9F77723BBA05458042D68206F7252682DBA3663ED"),
    (b"\xff" * 7, 0x0B, 32, "8DEEAA1AEC47CCEE569F659C21DFA8E112DB3CEE37B18178B2ACD805B799CC37"),
    (b"\xff", 0x30, 32, "553122E2135E363C3292BED2C6421FA232BAB03DAA07C7D6636603286506325B"),
    (b"\xff" * 3, 0x7F, 32, "16274CC656D44CEFD422395D0F9053BDA6D28E122ABA15C765E5AD0E6EAF26F9"),
]
TURBOSHAKE256 = [
    (b"", 0x1F, 64, "367A329DAFEA871C7802EC67F905AE13C57695DC2C6663C61035F59A18F8E7DB11EDC0E12E91EA60EB6B32DF06DD7F002FBAFABB6E13EC1CC20D995547600DB0"),
    (ptn(1), 0x1F, 64, "3E1712F928F8EAF1054632B2AA0A246ED8B0C378728F60BC970410155C28820E90CC90D8A3006AA2372C5C5EA176B0682BF22BAE7467AC94F74D43D39B0482E2"),
]


@pytest.mark.parametrize(("message", "domain", "length", "expected"), TURBOSHAKE128)
def test_turboshake128_rfc9861(message: bytes, domain: int, length: int, expected: str) -> None:
    assert dhash.turboshake128(message, length, domain=domain) == unhex(expected)
    assert dhash.TurboShake128(message, domain=domain).digest(length) == unhex(expected)


@pytest.mark.parametrize(("message", "domain", "length", "expected"), TURBOSHAKE256)
def test_turboshake256_rfc9861(message: bytes, domain: int, length: int, expected: str) -> None:
    assert dhash.turboshake256(message, length, domain=domain) == unhex(expected)
    assert dhash.TurboShake256(message, domain=domain).digest(length) == unhex(expected)


def test_turboshake_long_output_tail_rfc9861() -> None:
    reader = dhash.TurboShake128().reader()
    reader.read(10032 - 32)
    assert reader.read(32) == unhex(
        "A3B9B0385900CE761F22AED548E754DA10A5242D62E8C658E3F3A923A7555607"
    )


@pytest.mark.parametrize("domain", [0x00, 0x80])
def test_xof_domain_bounds(domain: int) -> None:
    with pytest.raises(InvalidInputError):
        dhash.TurboShake128(domain=domain)
    with pytest.raises(InvalidInputError):
        dhash.turboshake256(b"", 32, domain=domain)


def test_concurrent_updates_to_one_hasher_are_serialized() -> None:
    import threading

    # Each update is large enough to run with the GIL released.
    chunk = bytes(range(256)) * 64
    shared = dhash.Blake2b()

    def work() -> None:
        for _ in range(50):
            shared.update(chunk)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert shared.digest() == dhash.blake2b(chunk * 200)
