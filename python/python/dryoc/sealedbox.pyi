from typing import ClassVar, Self, final

from typing_extensions import Buffer

from dryoc.kem.xwing import KeyPair, PublicKey, SecretKey

__all__ = ["SealedBox"]

@final
class SealedBox:
    """Anonymous post-quantum public-key encryption: an HPKE (RFC 9180) sealed
    box using X-Wing, HKDF-SHA256 and ChaCha20-Poly1305.

    Anyone with the recipient's `dryoc.kem.xwing.PublicKey` can encrypt;
    only the holder of the matching `KeyPair` can decrypt. Recorded boxes
    stay confidential even if X25519 is later broken.
    """

    OVERHEAD: ClassVar[int]
    """Bytes a sealed box adds to the plaintext."""
    __hash__: ClassVar[None]
    def __new__(cls, recipient: PublicKey | KeyPair | SecretKey) -> Self:
        """Creates a sealed box for a recipient.

        Pass the recipient's X-Wing `PublicKey` to encrypt only, or the
        recipient's `KeyPair` (or `SecretKey`) to also decrypt.
        """
    @property
    def public_key(self) -> PublicKey:
        """The recipient's public key."""
    def encrypt(self, plaintext: Buffer) -> bytes:
        """Encrypts `plaintext` for the recipient, returning
        `encapsulated_key || ciphertext || tag`.
        """
    def decrypt(self, ciphertext: Buffer) -> bytes:
        """Decrypts a sealed box. Requires the recipient's key pair.

        Raises `CryptoError` if the box was modified or is for another key.
        """
