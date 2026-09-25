"""ML-KEM-768 and X-Wing known answers (vectors vendored in the Rust crate),
and the X-Wing sealed box."""

import pytest
from conftest import flip, load_vectors

from dryoc import CryptoError, DryocError, InvalidInputError
from dryoc.kem import mlkem768, xwing
from dryoc.sealedbox import SealedBox


def test_mlkem768_acvp_keygen() -> None:
    for record in load_vectors("mlkem768_acvp_keygen.txt"):
        pair = mlkem768.KeyPair.from_seed(bytes.fromhex(record["d"] + record["z"]))
        assert bytes(pair.public_key) == bytes.fromhex(record["ek"]), record["tcid"]
        assert bytes(pair.secret_key) == bytes.fromhex(record["dk"]), record["tcid"]
        rebuilt = mlkem768.KeyPair.from_secret_key(bytes.fromhex(record["dk"]))
        assert rebuilt == pair


def test_mlkem768_acvp_decapsulation_including_implicit_rejection() -> None:
    reasons = set()
    for record in load_vectors("mlkem768_acvp_decap.txt"):
        pair = mlkem768.KeyPair.from_secret_key(mlkem768.SecretKey(bytes.fromhex(record["dk"])))
        shared = pair.decapsulate(bytes.fromhex(record["c"]))
        assert shared == bytes.fromhex(record["k"]), record["tcid"]
        reasons.add(record["reason"])
    assert reasons == {"valid decapsulation", "modified ciphertext"}


def test_mlkem768_acvp_encapsulation_key_check() -> None:
    for record in load_vectors("mlkem768_acvp_ek_check.txt"):
        public_key = mlkem768.PublicKey(bytes.fromhex(record["ek"]))
        if record["valid"] == "true":
            ciphertext, shared = public_key.encapsulate()
            assert len(ciphertext) == mlkem768.PublicKey.CIPHERTEXT_SIZE
            assert len(shared) == mlkem768.PublicKey.SHARED_SECRET_SIZE
        else:
            with pytest.raises(InvalidInputError):
                public_key.encapsulate()


def test_xwing_draft_vectors() -> None:
    for record in load_vectors("xwing_draft.txt"):
        pair = xwing.KeyPair.from_seed(bytes.fromhex(record["seed"]))
        assert bytes(pair.public_key) == bytes.fromhex(record["pk"]), record["index"]
        assert bytes(pair.secret_key) == bytes.fromhex(record["seed"])
        assert pair.decapsulate(bytes.fromhex(record["ct"])) == bytes.fromhex(record["ss"])


def test_xwing_libsodium_edge_cases() -> None:
    for record in load_vectors("xwing_libsodium_edge.txt"):
        name, op, rc = record["name"], record["op"], record["rc"]
        if op == "enc_deterministic":
            public_key = xwing.PublicKey(bytes.fromhex(record["pk"]))
            if rc == "0":
                public_key.encapsulate()
            else:
                with pytest.raises(DryocError):
                    public_key.encapsulate()
        else:
            assert op == "dec", name
            pair = xwing.KeyPair.from_secret_key(bytes.fromhex(record["sk"]))
            ciphertext = bytes.fromhex(record["ct"])
            if rc == "0":
                assert pair.decapsulate(ciphertext) == bytes.fromhex(record["ss"]), name
            else:
                with pytest.raises(DryocError):
                    pair.decapsulate(ciphertext)


@pytest.mark.parametrize("module", [xwing, mlkem768], ids=["xwing", "mlkem768"])
def test_encapsulation_roundtrip(module) -> None:  # type: ignore[no-untyped-def]
    pair = module.KeyPair.generate()
    ciphertext, shared = pair.public_key.encapsulate()
    assert pair.decapsulate(bytearray(ciphertext)) == shared
    # Implicit rejection: a modified ciphertext yields an unrelated secret.
    assert pair.decapsulate(flip(ciphertext, 1)) != shared
    with pytest.raises(InvalidInputError, match="ciphertext must be exactly"):
        pair.decapsulate(ciphertext[:-1])
    with pytest.raises(InvalidInputError):
        module.KeyPair.from_seed(bytes(module.KeyPair.SEED_SIZE - 1))


def test_xwing_sealed_box() -> None:
    recipient = xwing.KeyPair.generate()
    sealed = SealedBox(recipient.public_key).encrypt(b"quantum-safe")
    assert len(sealed) == len(b"quantum-safe") + SealedBox.OVERHEAD
    assert SealedBox(recipient).decrypt(sealed) == b"quantum-safe"
    assert SealedBox(recipient.secret_key).decrypt(memoryview(sealed)) == b"quantum-safe"
    for index in (0, SealedBox.OVERHEAD - 17, len(sealed) - 1):
        with pytest.raises(CryptoError):
            SealedBox(recipient).decrypt(flip(sealed, index))
    with pytest.raises(CryptoError):
        SealedBox(xwing.KeyPair.generate()).decrypt(sealed)
    with pytest.raises(InvalidInputError):
        SealedBox(recipient).decrypt(sealed[: SealedBox.OVERHEAD - 1])
    with pytest.raises(TypeError, match="cannot decrypt"):
        SealedBox(recipient.public_key).decrypt(sealed)
    with pytest.raises(TypeError):
        SealedBox(mlkem768.KeyPair.generate())  # type: ignore[arg-type]
