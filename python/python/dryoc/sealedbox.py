"""Post-quantum anonymous public-key encryption.

A sealed box is an HPKE (RFC 9180) message using X-Wing (ML-KEM-768 +
X25519), HKDF-SHA256 and ChaCha20-Poly1305, so recorded ciphertexts stay
confidential even against a future quantum computer. Recipients use
:class:`dryoc.kem.xwing.KeyPair` keys.

Example::

    from dryoc.kem.xwing import KeyPair
    from dryoc.sealedbox import SealedBox

    recipient = KeyPair.generate()
    sealed = SealedBox(recipient.public_key).encrypt(b"for your eyes only")
    assert SealedBox(recipient).decrypt(sealed) == b"for your eyes only"
"""

from dryoc._dryoc import sealedbox_SealedBox as SealedBox

__all__ = ["SealedBox"]
