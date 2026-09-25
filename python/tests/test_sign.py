"""Ed25519 and Ed25519ph signatures."""

from __future__ import annotations

import pytest
from conftest import BUFFER_TYPES, flip

from dryoc import CryptoError, DryocError, InvalidInputError
from dryoc.sign import Ed25519ph, SigningKey, VerifyKey

# RFC 8032 section 7.1, TEST 1 and TEST 3 (Ed25519).
RFC8032_ED25519 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]

# RFC 8032 section 7.3, TEST abc (Ed25519ph, empty context).
RFC8032_ED25519PH = (
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "616263",
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
)


@pytest.mark.parametrize(("seed", "public", "message", "signature"), RFC8032_ED25519)
def test_rfc8032_ed25519(seed: str, public: str, message: str, signature: str) -> None:
    key = SigningKey.from_seed(bytes.fromhex(seed))
    assert bytes(key.verify_key) == bytes.fromhex(public)
    assert key.to_seed() == bytes.fromhex(seed)
    assert bytes(key) == bytes.fromhex(seed + public)
    assert key.sign(bytes.fromhex(message)) == bytes.fromhex(signature)
    VerifyKey(bytes.fromhex(public)).verify(bytes.fromhex(signature), bytes.fromhex(message))


def test_rfc8032_ed25519ph() -> None:
    seed, public, message, signature = (bytes.fromhex(h) for h in RFC8032_ED25519PH)
    key = SigningKey.from_seed(seed)
    signer = Ed25519ph()
    signer.update(message[:1])
    signer.update(message[1:])
    assert signer.sign(key) == signature
    Ed25519ph(message).verify(signature, VerifyKey(public))
    with pytest.raises(CryptoError):
        Ed25519ph(message + b"!").verify(signature, key.verify_key)
    # Ed25519ph signatures are not Ed25519 signatures.
    with pytest.raises(CryptoError):
        key.verify_key.verify(signature, message)


def test_ed25519ph_is_single_use() -> None:
    signer = Ed25519ph(b"data")
    signer.sign(SigningKey.generate())
    with pytest.raises(DryocError):
        signer.update(b"more")
    with pytest.raises(DryocError):
        signer.sign(SigningKey.generate())


@pytest.mark.parametrize("make", BUFFER_TYPES)
def test_sign_and_verify_bytes_like(make) -> None:  # type: ignore[no-untyped-def]
    key = SigningKey.generate()
    signature = key.sign(make(b"message"))
    key.verify_key.verify(make(signature), make(b"message"))
    assert SigningKey(make(bytes(key))) == key


def test_verification_failures_raise() -> None:
    key = SigningKey.generate()
    signature = key.sign(b"message")
    with pytest.raises(CryptoError):
        key.verify_key.verify(flip(signature, 0), b"message")
    with pytest.raises(CryptoError):
        key.verify_key.verify(signature, b"messagE")
    with pytest.raises(CryptoError):
        SigningKey.generate().verify_key.verify(signature, b"message")
    with pytest.raises(InvalidInputError):
        key.verify_key.verify(signature[:-1], b"message")


def test_combined_format() -> None:
    key = SigningKey.generate()
    signed = key.sign_combined(b"payload")
    assert signed == key.sign(b"payload") + b"payload"
    assert key.verify_key.verify_combined(signed) == b"payload"
    with pytest.raises(CryptoError):
        key.verify_key.verify_combined(flip(signed, -1))
    with pytest.raises(InvalidInputError):
        key.verify_key.verify_combined(signed[:63])


def test_secret_key_import_recomputes_public_half() -> None:
    key = SigningKey.generate()
    tampered = bytes(key)[:32] + bytes(32)
    assert SigningKey(tampered) == key
    assert SigningKey.from_bytes(bytes(key)).verify_key == key.verify_key


def test_signing_key_lengths() -> None:
    with pytest.raises(InvalidInputError, match="exactly 64"):
        SigningKey(bytes(32))
    with pytest.raises(InvalidInputError, match="exactly 32"):
        SigningKey.from_seed(bytes(64))
    with pytest.raises(InvalidInputError, match="exactly 32"):
        VerifyKey(bytes(31))
