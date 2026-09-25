"""Interoperability with libsodium through PyNaCl (a test-only dependency).

Each test produces data with one library and consumes it with the other.
"""

from __future__ import annotations

import pytest

nacl = pytest.importorskip(
    "nacl",
    reason="PyNaCl (libsodium) is not installed or has no wheel for this platform; "
    "libsodium interoperability tests are skipped",
)

import nacl.bindings as sodium  # noqa: E402
import nacl.encoding  # noqa: E402
import nacl.hash  # noqa: E402
import nacl.public  # noqa: E402
import nacl.pwhash.argon2i  # noqa: E402
import nacl.pwhash.argon2id  # noqa: E402
import nacl.secret  # noqa: E402
import nacl.signing  # noqa: E402
import nacl.utils  # noqa: E402

import dryoc  # noqa: E402
from dryoc import aead, box, hash, kx, pwhash, secretbox, secretstream, sign  # noqa: E402

MESSAGES = [b"", b"x", b"The quick brown fox jumps over the lazy dog", bytes(range(256)) * 20]


@pytest.mark.parametrize("message", MESSAGES)
def test_secretbox(message: bytes) -> None:
    key = dryoc.random_bytes(32)
    nonce = dryoc.random_bytes(24)
    theirs = nacl.secret.SecretBox(key).encrypt(message, nonce)
    ours = secretbox.SecretBox(key).encrypt(message, nonce)
    assert ours.ciphertext == theirs.ciphertext
    assert secretbox.SecretBox(key).decrypt(theirs.ciphertext, theirs.nonce) == message
    assert nacl.secret.SecretBox(key).decrypt(ours.ciphertext, ours.nonce) == message


@pytest.mark.parametrize("message", MESSAGES)
def test_box(message: bytes) -> None:
    alice, bob = nacl.public.PrivateKey.generate(), box.KeyPair.generate()
    bob_public = nacl.public.PublicKey(bytes(bob.public_key))
    alice_public = box.PublicKey(bytes(alice.public_key))

    theirs = nacl.public.Box(alice, bob_public).encrypt(message)
    assert box.Box(bob, alice_public).decrypt(theirs.ciphertext, theirs.nonce) == message

    ours = box.Box(bob, alice_public).encrypt(message)
    bob_private = nacl.public.PrivateKey(bytes(bob.secret_key))
    assert nacl.public.Box(alice, bob_private.public_key).decrypt(ours.ciphertext, ours.nonce) == message
    assert nacl.public.Box(alice, bob_public).encrypt(message, ours.nonce).ciphertext == ours.ciphertext


def test_box_key_derivation_from_seed() -> None:
    seed = bytes(range(32))
    theirs = nacl.public.PrivateKey.from_seed(seed)
    ours = box.KeyPair.from_seed(seed)
    assert bytes(ours.secret_key) == bytes(theirs)
    assert bytes(ours.public_key) == bytes(theirs.public_key)


@pytest.mark.parametrize("message", MESSAGES)
def test_sealed_box(message: bytes) -> None:
    ours = box.KeyPair.generate()
    theirs = nacl.public.PrivateKey(bytes(ours.secret_key))
    sealed_by_them = nacl.public.SealedBox(theirs.public_key).encrypt(message)
    assert box.SealedBox(ours).decrypt(sealed_by_them) == message
    sealed_by_us = box.SealedBox(ours.public_key).encrypt(message)
    assert nacl.public.SealedBox(theirs).decrypt(sealed_by_us) == message


@pytest.mark.parametrize("message", MESSAGES)
def test_sign(message: bytes) -> None:
    seed = dryoc.random_bytes(32)
    theirs = nacl.signing.SigningKey(seed)
    ours = sign.SigningKey.from_seed(seed)
    assert bytes(ours.verify_key) == bytes(theirs.verify_key)
    assert bytes(ours) == bytes(theirs._signing_key)
    signed = theirs.sign(message)
    assert ours.sign(message) == signed.signature
    assert ours.sign_combined(message) == bytes(signed)
    ours.verify_key.verify(signed.signature, message)
    assert ours.verify_key.verify_combined(bytes(signed)) == message
    assert theirs.verify_key.verify(ours.sign_combined(message)) == message


def test_ed25519ph() -> None:
    ours = sign.SigningKey.generate()
    message = bytes(range(256)) * 50
    state = sodium.crypto_sign_ed25519ph_state()
    sodium.crypto_sign_ed25519ph_update(state, message)
    theirs = sodium.crypto_sign_ed25519ph_final_create(state, bytes(ours))
    signer = sign.Ed25519ph(message)
    assert signer.sign(ours) == theirs
    sign.Ed25519ph(message).verify(theirs, ours.verify_key)


@pytest.mark.parametrize("message", MESSAGES)
def test_aeads(message: bytes) -> None:
    key, aad = dryoc.random_bytes(32), b"associated"
    xnonce, nonce = dryoc.random_bytes(24), dryoc.random_bytes(12)

    x = aead.XChaCha20Poly1305(key)
    theirs = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, aad, xnonce, key)
    assert x.encrypt(message, xnonce, associated_data=aad).ciphertext == theirs
    assert x.decrypt(theirs, xnonce, associated_data=aad) == message
    envelope = x.seal(message, associated_data=aad)
    opened = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(envelope[24:], aad, envelope[:24], key)
    assert opened == message

    c = aead.ChaCha20Poly1305(key)
    theirs = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(message, aad, nonce, key)
    assert c.encrypt(message, nonce, associated_data=aad).ciphertext == theirs
    assert c.decrypt(theirs, nonce, associated_data=aad) == message
    with pytest.raises(dryoc.CryptoError):
        c.decrypt(theirs, nonce)


def test_secretstream_libsodium_to_dryoc() -> None:
    key = sodium.crypto_secretstream_xchacha20poly1305_keygen()
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    parts = [(b"first", 0, None), (b"second", 1, b"ad"), (b"", 2, None), (b"last", 3, None)]
    chunks = [
        sodium.crypto_secretstream_xchacha20poly1305_push(state, m, ad, tag) for m, tag, ad in parts
    ]
    with secretstream.Decryptor(secretstream.Key(key), header) as decryptor:
        for chunk, (message, tag, ad) in zip(chunks, parts, strict=True):
            assert decryptor.pull(chunk, associated_data=ad) == (message, secretstream.Tag(tag))


def test_secretstream_dryoc_to_libsodium() -> None:
    key = secretstream.Key.generate()
    tags = [secretstream.Tag.MESSAGE, secretstream.Tag.PUSH, secretstream.Tag.REKEY, secretstream.Tag.FINAL]
    with secretstream.Encryptor(key) as encryptor:
        chunks = [encryptor.push(b"part %d" % i, tag=tag) for i, tag in enumerate(tags)]
        encryptor_header = encryptor.header
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, encryptor_header, bytes(key))
    for i, (chunk, tag) in enumerate(zip(chunks, tags, strict=True)):
        assert sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk) == (b"part %d" % i, tag)


def test_secretstream_explicit_rekey() -> None:
    key = secretstream.Key.generate()
    encryptor = secretstream.Encryptor(key)
    first = encryptor.push(b"a")
    encryptor.rekey()
    second = encryptor.push(b"b", tag=secretstream.Tag.FINAL)
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, encryptor.header, bytes(key))
    assert sodium.crypto_secretstream_xchacha20poly1305_pull(state, first) == (b"a", 0)
    sodium.crypto_secretstream_xchacha20poly1305_rekey(state)
    assert sodium.crypto_secretstream_xchacha20poly1305_pull(state, second) == (b"b", 3)


@pytest.mark.parametrize("message", MESSAGES)
def test_generichash_and_sha2(message: bytes) -> None:
    raw = nacl.encoding.RawEncoder
    assert hash.blake2b(message) == nacl.hash.blake2b(message, encoder=raw)
    for size in (16, 32, 64):
        key = bytes(range(size))
        expected = nacl.hash.blake2b(message, digest_size=size, key=key, encoder=raw)
        assert hash.Blake2b(message, digest_size=size, key=key).digest() == expected
    assert hash.sha256(message) == nacl.hash.sha256(message, encoder=raw)
    assert hash.sha512(message) == nacl.hash.sha512(message, encoder=raw)


def test_kx() -> None:
    client = box.KeyPair.generate()
    server_public, server_secret = sodium.crypto_kx_keypair()
    ours = kx.client_session_keys(client, box.PublicKey(server_public))
    theirs = sodium.crypto_kx_server_session_keys(
        server_public, server_secret, bytes(client.public_key)
    )
    assert (ours.rx, ours.tx) == (theirs[1], theirs[0])
    server = box.KeyPair.from_secret_key(server_secret)
    assert tuple(kx.server_session_keys(server, client.public_key)) == theirs
    assert sodium.crypto_kx_client_session_keys(
        bytes(client.public_key), bytes(client.secret_key), server_public
    ) == tuple(ours)


FAST_ID = (nacl.pwhash.argon2id.OPSLIMIT_MIN, nacl.pwhash.argon2id.MEMLIMIT_MIN)
FAST_I = (nacl.pwhash.argon2i.OPSLIMIT_MIN, nacl.pwhash.argon2i.MEMLIMIT_MIN)


@pytest.mark.parametrize(
    ("module", "algorithm", "limits"),
    [
        (nacl.pwhash.argon2id, pwhash.Algorithm.ARGON2ID13, FAST_ID),
        (nacl.pwhash.argon2i, pwhash.Algorithm.ARGON2I13, FAST_I),
    ],
    ids=["argon2id", "argon2i"],
)
def test_pwhash(module, algorithm, limits) -> None:  # type: ignore[no-untyped-def]
    opslimit, memlimit = limits
    password = b"correct horse battery staple"
    theirs = module.str(password, opslimit=opslimit, memlimit=memlimit).decode()
    pwhash.verify(theirs, password)
    with pytest.raises(dryoc.CryptoError):
        pwhash.verify(theirs, b"wrong")
    ours = pwhash.hash(password, opslimit=opslimit, memlimit=memlimit, algorithm=algorithm)
    assert module.verify(ours.encode(), password)

    salt = bytes(range(16))
    expected = module.kdf(48, password, salt, opslimit=opslimit, memlimit=memlimit)
    derived = pwhash.derive_key(
        password, salt, length=48, opslimit=opslimit, memlimit=memlimit, algorithm=algorithm
    )
    assert derived == expected


def test_pwhash_interactive_preset_matches_libsodium() -> None:
    stored = pwhash.hash(b"pw")
    assert f"m={nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE // 1024}," in stored
    assert f"t={nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE}," in stored
    assert nacl.pwhash.argon2id.verify(stored.encode(), b"pw")
