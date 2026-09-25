from typing import ClassVar, final

from typing_extensions import Buffer, Self

from dryoc.kem.xwing import KeyPair, PublicKey, SecretKey

__all__ = ["SealedBox"]

@final
class SealedBox:
    """Anonymous post-quantum public-key encryption (HPKE with X-Wing)."""

    OVERHEAD: ClassVar[int]
    __hash__: ClassVar[None]  # type: ignore[assignment]
    def __new__(cls, recipient: PublicKey | KeyPair | SecretKey) -> Self: ...
    @property
    def public_key(self) -> PublicKey: ...
    def encrypt(self, plaintext: Buffer) -> bytes: ...
    def decrypt(self, ciphertext: Buffer) -> bytes: ...
