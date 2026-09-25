"""SecretBox and the ChaCha20-Poly1305 AEADs."""

import pytest
from conftest import BUFFER_TYPES, flip

from dryoc import CryptoError, EncryptedMessage, InvalidInputError
from dryoc.aead import ChaCha20Poly1305, XChaCha20Poly1305
from dryoc.secretbox import SecretBox

# RFC 8439 section 2.8.2 (AEAD_CHACHA20_POLY1305).
RFC8439_KEY = bytes(range(0x80, 0xA0))
RFC8439_NONCE = bytes.fromhex("070000004041424344454647")
RFC8439_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC8439_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
    b"the future, sunscreen would be it."
)
RFC8439_CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
)
RFC8439_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")


def test_rfc8439_chacha20poly1305_known_answer() -> None:
    key = ChaCha20Poly1305(RFC8439_KEY)
    sealed = key.encrypt(RFC8439_PLAINTEXT, RFC8439_NONCE, associated_data=RFC8439_AAD)
    assert sealed == EncryptedMessage(RFC8439_CIPHERTEXT + RFC8439_TAG, RFC8439_NONCE)
    assert key.decrypt(*sealed, associated_data=RFC8439_AAD) == RFC8439_PLAINTEXT


@pytest.mark.parametrize("cls", [SecretBox, XChaCha20Poly1305])
def test_random_nonce_roundtrip(cls: type[SecretBox] | type[XChaCha20Poly1305]) -> None:
    key = cls.generate()
    first, second = key.encrypt(b"message"), key.encrypt(b"message")
    assert len(first.nonce) == cls.NONCE_SIZE
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert key.decrypt(*first) == b"message"
    assert key.decrypt(first.ciphertext, first.nonce) == b"message"


def test_secretbox_explicit_nonce_is_deterministic_and_libsodium_sized() -> None:
    key = SecretBox(bytes(32))
    nonce = bytes(24)
    first = key.encrypt(b"abc", nonce)
    assert first == key.encrypt(b"abc", nonce=nonce)
    assert len(first.ciphertext) == 3 + SecretBox.MAC_SIZE
    assert first.nonce == nonce


@pytest.mark.parametrize("make", BUFFER_TYPES)
def test_bytes_like_inputs(make) -> None:  # type: ignore[no-untyped-def]
    raw = bytes(range(32))
    key = SecretBox(make(raw))
    sealed = key.encrypt(make(b"payload"), make(bytes(24)))
    assert key.decrypt(make(sealed.ciphertext), make(sealed.nonce)) == b"payload"

    aead = XChaCha20Poly1305.from_bytes(make(raw))
    envelope = aead.seal(make(b"payload"), associated_data=make(b"aad"))
    assert aead.open(make(envelope), associated_data=make(b"aad")) == b"payload"


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda m: (flip(m.ciphertext, 0), m.nonce), id="tag"),
        pytest.param(lambda m: (flip(m.ciphertext, -1), m.nonce), id="ciphertext"),
        pytest.param(lambda m: (m.ciphertext, flip(m.nonce, 5)), id="nonce"),
        pytest.param(lambda m: (m.ciphertext[:-1], m.nonce), id="truncated"),
    ],
)
def test_secretbox_tampering_raises(tamper) -> None:  # type: ignore[no-untyped-def]
    key = SecretBox.generate()
    with pytest.raises(CryptoError):
        key.decrypt(*tamper(key.encrypt(b"some secret message")))


def test_secretbox_wrong_key_raises() -> None:
    sealed = SecretBox.generate().encrypt(b"x")
    with pytest.raises(CryptoError):
        SecretBox.generate().decrypt(*sealed)


def test_secretbox_ciphertext_shorter_than_tag_is_invalid_input() -> None:
    with pytest.raises(InvalidInputError):
        SecretBox.generate().decrypt(b"short", bytes(24))


@pytest.mark.parametrize("cls", [XChaCha20Poly1305, ChaCha20Poly1305])
def test_aead_rejects_modified_ciphertext_and_associated_data(
    cls: type[XChaCha20Poly1305] | type[ChaCha20Poly1305],
) -> None:
    key = cls.generate()
    nonce = bytes(cls.NONCE_SIZE)
    sealed = key.encrypt(b"body", nonce, associated_data=b"header")
    assert key.decrypt(*sealed, associated_data=b"header") == b"body"
    with pytest.raises(CryptoError):
        key.decrypt(*sealed)
    with pytest.raises(CryptoError):
        key.decrypt(*sealed, associated_data=b"headeR")
    with pytest.raises(CryptoError):
        key.decrypt(flip(sealed.ciphertext, -1), nonce, associated_data=b"header")


def test_xchacha_envelope_layout_and_tampering() -> None:
    key = XChaCha20Poly1305.generate()
    envelope = key.seal(b"body")
    size = XChaCha20Poly1305.NONCE_SIZE
    assert len(envelope) == size + 4 + XChaCha20Poly1305.TAG_SIZE
    # The envelope is nonce || ciphertext || tag, as dryoc's Rust AeadEnvelope.
    assert key.decrypt(envelope[size:], envelope[:size]) == b"body"
    for index in (0, size, len(envelope) - 1):
        with pytest.raises(CryptoError):
            key.open(flip(envelope, index))
    with pytest.raises(InvalidInputError):
        key.open(envelope[: size + 3])


def test_chacha20poly1305_requires_a_nonce() -> None:
    key = ChaCha20Poly1305.generate()
    with pytest.raises(TypeError):
        key.encrypt(b"x")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("call", "match"),
    [
        (lambda: SecretBox(bytes(31)), "secretbox key must be exactly 32 bytes long, got 31"),
        (lambda: SecretBox.generate().encrypt(b"x", bytes(23)), "nonce must be exactly 24"),
        (lambda: SecretBox.generate().decrypt(bytes(20), bytes(25)), "nonce must be exactly 24"),
        (lambda: XChaCha20Poly1305(bytes(33)), "key must be exactly 32"),
        (lambda: ChaCha20Poly1305.generate().encrypt(b"x", bytes(24)), "exactly 12"),
    ],
)
def test_wrong_lengths_raise_value_error(call, match: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match=match) as info:
        call()
    assert isinstance(info.value, InvalidInputError)


@pytest.mark.parametrize("cls", [SecretBox, XChaCha20Poly1305])
def test_large_message_roundtrip(cls: type[SecretBox] | type[XChaCha20Poly1305]) -> None:
    # Inputs this large are processed with the GIL released.
    key = cls.generate()
    data = bytearray(b"z" * (1 << 20))
    sealed = key.encrypt(data)
    assert key.decrypt(memoryview(sealed.ciphertext), sealed.nonce) == data
