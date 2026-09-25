"""Post-quantum key encapsulation.

* :mod:`dryoc.kem.xwing` -- X-Wing, the hybrid of ML-KEM-768 and X25519
  (libsodium's ``crypto_kem``). Prefer it: it stays secure if either
  component does.
* :mod:`dryoc.kem.mlkem768` -- ML-KEM-768 (FIPS 203) alone, for protocols
  that require it.

Example::

    from dryoc.kem import xwing

    recipient = xwing.KeyPair.generate()
    ciphertext, sender_secret = recipient.public_key.encapsulate()
    assert recipient.decapsulate(ciphertext) == sender_secret
"""

from dryoc.kem import mlkem768, xwing

__all__ = ["mlkem768", "xwing"]
