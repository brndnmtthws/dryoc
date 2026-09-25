"""Public-key boxes, sealed boxes and key exchange."""

from __future__ import annotations

import pytest
from conftest import BUFFER_TYPES, flip

from dryoc import CryptoError, InvalidInputError, kx
from dryoc.box import Box, KeyPair, PublicKey, SealedBox, SecretKey

# RFC 7748 section 6.1 (X25519 Diffie-Hellman).
ALICE_SECRET = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_SECRET = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUBLIC = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")


def test_rfc7748_public_key_derivation() -> None:
    assert bytes(KeyPair.from_secret_key(ALICE_SECRET).public_key) == ALICE_PUBLIC
    assert bytes(SecretKey(BOB_SECRET).public_key) == BOB_PUBLIC
    pair = KeyPair.from_secret_key(SecretKey(BOB_SECRET))
    assert bytes(pair.secret_key) == BOB_SECRET


def test_seeded_key_pairs_are_deterministic() -> None:
    seed = bytes(range(32))
    assert KeyPair.from_seed(seed) == KeyPair.from_seed(bytearray(seed))
    assert KeyPair.from_seed(seed) != KeyPair.from_seed(bytes(32))


def test_box_roundtrip_both_directions() -> None:
    alice, bob = KeyPair.from_secret_key(ALICE_SECRET), KeyPair.from_secret_key(BOB_SECRET)
    to_bob = Box(alice, bob.public_key)
    from_alice = Box(bob.secret_key, PublicKey(ALICE_PUBLIC))
    message = to_bob.encrypt(b"hello bob")
    assert len(message.ciphertext) == len(b"hello bob") + Box.MAC_SIZE
    assert from_alice.decrypt(*message) == b"hello bob"
    reply = from_alice.encrypt(b"hi alice", bytes(24))
    assert to_bob.decrypt(*reply) == b"hi alice"


@pytest.mark.parametrize("make", BUFFER_TYPES)
def test_box_bytes_like_inputs(make) -> None:  # type: ignore[no-untyped-def]
    alice, bob = KeyPair.generate(), KeyPair.generate()
    message = Box(alice, bob.public_key).encrypt(make(b"data"), make(bytes(24)))
    assert Box(bob, alice.public_key).decrypt(make(message.ciphertext), make(message.nonce)) == b"data"


def test_box_rejects_tampering_and_wrong_keys() -> None:
    alice, bob, eve = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    message = Box(alice, bob.public_key).encrypt(b"secret")
    receiver = Box(bob, alice.public_key)
    with pytest.raises(CryptoError):
        receiver.decrypt(flip(message.ciphertext, 3), message.nonce)
    with pytest.raises(CryptoError):
        receiver.decrypt(message.ciphertext, flip(message.nonce, 0))
    with pytest.raises(CryptoError):
        Box(bob, eve.public_key).decrypt(*message)


def test_box_rejects_low_order_public_key() -> None:
    with pytest.raises(InvalidInputError):
        Box(KeyPair.generate(), PublicKey(bytes(32)))


def test_sealed_box_roundtrip_and_overhead() -> None:
    bob = KeyPair.generate()
    sealed = SealedBox(bob.public_key).encrypt(b"anonymous")
    assert len(sealed) == len(b"anonymous") + SealedBox.OVERHEAD
    assert SealedBox(bob).decrypt(sealed) == b"anonymous"
    assert SealedBox(bob.secret_key).decrypt(bytearray(sealed)) == b"anonymous"
    assert SealedBox(bob).public_key == bob.public_key


def test_sealed_box_failures() -> None:
    bob = KeyPair.generate()
    sealed = SealedBox(bob.public_key).encrypt(b"anonymous")
    for index in (0, 32, len(sealed) - 1):
        with pytest.raises(CryptoError):
            SealedBox(bob).decrypt(flip(sealed, index))
    with pytest.raises(CryptoError):
        SealedBox(KeyPair.generate()).decrypt(sealed)
    with pytest.raises(InvalidInputError):
        SealedBox(bob).decrypt(sealed[: SealedBox.OVERHEAD - 1])
    with pytest.raises(TypeError, match="cannot decrypt"):
        SealedBox(bob.public_key).decrypt(sealed)
    with pytest.raises(TypeError):
        SealedBox(bytes(bob.public_key))  # type: ignore[arg-type]


def test_kx_session_keys_match_between_client_and_server() -> None:
    client, server = KeyPair.generate(), KeyPair.generate()
    client_keys = kx.client_session_keys(client, server.public_key)
    server_keys = kx.server_session_keys(server, client.public_key)
    assert client_keys.rx == server_keys.tx
    assert client_keys.tx == server_keys.rx
    assert client_keys.rx != client_keys.tx
    rx, tx = client_keys
    assert len(rx) == len(tx) == 32
    assert "redacted" in repr(client_keys)
    assert rx.hex() not in repr(client_keys)
    # Deterministic for the same key pairs; compared in constant time.
    assert kx.client_session_keys(client, server.public_key) == client_keys
    assert client_keys != server_keys
    assert tuple(server_keys) == (client_keys.tx, client_keys.rx)


def test_kx_rejects_low_order_peer_key() -> None:
    with pytest.raises(InvalidInputError):
        kx.client_session_keys(KeyPair.generate(), PublicKey(bytes(32)))
