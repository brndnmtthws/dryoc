"""Native extension module. Import from the public ``dryoc.*`` modules instead."""

from typing import Any

from typing_extensions import Buffer

from dryoc.aead import ChaCha20Poly1305 as aead_ChaCha20Poly1305
from dryoc.aead import XChaCha20Poly1305 as aead_XChaCha20Poly1305
from dryoc.box import Box as box_Box
from dryoc.box import KeyPair as box_KeyPair
from dryoc.box import PublicKey as box_PublicKey
from dryoc.box import SealedBox as box_SealedBox
from dryoc.box import SecretKey as box_SecretKey
from dryoc.hash import Blake2b as hash_Blake2b
from dryoc.hash import Sha3_256 as hash_Sha3_256
from dryoc.hash import Sha3_512 as hash_Sha3_512
from dryoc.hash import Sha256 as hash_Sha256
from dryoc.hash import Sha512 as hash_Sha512
from dryoc.hash import Shake128 as hash_Shake128
from dryoc.hash import Shake128Reader as hash_Shake128Reader
from dryoc.hash import Shake256 as hash_Shake256
from dryoc.hash import Shake256Reader as hash_Shake256Reader
from dryoc.hash import TurboShake128 as hash_TurboShake128
from dryoc.hash import TurboShake128Reader as hash_TurboShake128Reader
from dryoc.hash import TurboShake256 as hash_TurboShake256
from dryoc.hash import TurboShake256Reader as hash_TurboShake256Reader
from dryoc.hash import blake2b as hash_blake2b
from dryoc.hash import sha3_256 as hash_sha3_256
from dryoc.hash import sha3_512 as hash_sha3_512
from dryoc.hash import sha256 as hash_sha256
from dryoc.hash import sha512 as hash_sha512
from dryoc.hash import shake128 as hash_shake128
from dryoc.hash import shake256 as hash_shake256
from dryoc.hash import turboshake128 as hash_turboshake128
from dryoc.hash import turboshake256 as hash_turboshake256
from dryoc.kdf import HkdfSha256 as kdf_HkdfSha256
from dryoc.kdf import HkdfSha512 as kdf_HkdfSha512
from dryoc.kdf import Kdf as kdf_Kdf
from dryoc.kdf import hkdf_sha256 as kdf_hkdf_sha256
from dryoc.kdf import hkdf_sha512 as kdf_hkdf_sha512
from dryoc.kem.mlkem768 import KeyPair as mlkem768_KeyPair
from dryoc.kem.mlkem768 import PublicKey as mlkem768_PublicKey
from dryoc.kem.mlkem768 import SecretKey as mlkem768_SecretKey
from dryoc.kem.xwing import KeyPair as xwing_KeyPair
from dryoc.kem.xwing import PublicKey as xwing_PublicKey
from dryoc.kem.xwing import SecretKey as xwing_SecretKey
from dryoc.kx import SessionKeys as kx_SessionKeys
from dryoc.kx import client_session_keys as kx_client_session_keys
from dryoc.kx import server_session_keys as kx_server_session_keys
from dryoc.mac import HmacSha256 as mac_HmacSha256
from dryoc.mac import HmacSha512 as mac_HmacSha512
from dryoc.mac import HmacSha512256 as mac_HmacSha512256
from dryoc.mac import Poly1305 as mac_Poly1305
from dryoc.mac import hmac_sha256 as mac_hmac_sha256
from dryoc.mac import hmac_sha512 as mac_hmac_sha512
from dryoc.mac import hmac_sha512256 as mac_hmac_sha512256
from dryoc.mac import poly1305 as mac_poly1305
from dryoc.sealedbox import SealedBox as sealedbox_SealedBox
from dryoc.secretbox import SecretBox as secretbox_SecretBox
from dryoc.secretstream import Decryptor as secretstream_Decryptor
from dryoc.secretstream import Encryptor as secretstream_Encryptor
from dryoc.secretstream import Key as secretstream_Key
from dryoc.sign import Ed25519ph as sign_Ed25519ph
from dryoc.sign import SigningKey as sign_SigningKey
from dryoc.sign import VerifyKey as sign_VerifyKey

__all__ = [
    "__version__",
    "aead_ChaCha20Poly1305",
    "aead_XChaCha20Poly1305",
    "box_Box",
    "box_KeyPair",
    "box_PublicKey",
    "box_SealedBox",
    "box_SecretKey",
    "hash_Blake2b",
    "hash_Sha256",
    "hash_Sha3_256",
    "hash_Sha3_512",
    "hash_Sha512",
    "hash_Shake128",
    "hash_Shake128Reader",
    "hash_Shake256",
    "hash_Shake256Reader",
    "hash_TurboShake128",
    "hash_TurboShake128Reader",
    "hash_TurboShake256",
    "hash_TurboShake256Reader",
    "hash_blake2b",
    "hash_sha256",
    "hash_sha3_256",
    "hash_sha3_512",
    "hash_sha512",
    "hash_shake128",
    "hash_shake256",
    "hash_turboshake128",
    "hash_turboshake256",
    "kdf_HkdfSha256",
    "kdf_HkdfSha512",
    "kdf_Kdf",
    "kdf_hkdf_sha256",
    "kdf_hkdf_sha512",
    "kx_SessionKeys",
    "kx_client_session_keys",
    "kx_server_session_keys",
    "mac_HmacSha256",
    "mac_HmacSha512",
    "mac_HmacSha512256",
    "mac_Poly1305",
    "mac_hmac_sha256",
    "mac_hmac_sha512",
    "mac_hmac_sha512256",
    "mac_poly1305",
    "mlkem768_KeyPair",
    "mlkem768_PublicKey",
    "mlkem768_SecretKey",
    "pwhash_constants",
    "pwhash_derive_key",
    "pwhash_hash_password",
    "pwhash_verify_password",
    "random_bytes",
    "sealedbox_SealedBox",
    "secretbox_SecretBox",
    "secretstream_Decryptor",
    "secretstream_Encryptor",
    "secretstream_Key",
    "sign_Ed25519ph",
    "sign_SigningKey",
    "sign_VerifyKey",
    "xwing_KeyPair",
    "xwing_PublicKey",
    "xwing_SecretKey",
]

__version__: str

def random_bytes(size: int) -> bytes:
    """Returns ``size`` cryptographically secure random bytes."""

pwhash_constants: dict[str, Any]

def pwhash_hash_password(
    password: str | Buffer, opslimit: int, memlimit: int, algorithm: int
) -> str: ...
def pwhash_verify_password(encoded: str, password: str | Buffer) -> None: ...
def pwhash_derive_key(
    password: str | Buffer,
    salt: Buffer,
    length: int,
    opslimit: int,
    memlimit: int,
    algorithm: int,
) -> bytes: ...
