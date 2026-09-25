"""Session-key exchange over X25519, compatible with libsodium's ``crypto_kx``.

Both sides use :class:`dryoc.box.KeyPair` key pairs. Example::

    from dryoc import kx

    client, server = kx.KeyPair.generate(), kx.KeyPair.generate()
    client_keys = kx.client_session_keys(client, server.public_key)
    server_keys = kx.server_session_keys(server, client.public_key)
    assert client_keys.tx == server_keys.rx
"""

from __future__ import annotations

from dryoc._dryoc import box_KeyPair as KeyPair
from dryoc._dryoc import box_PublicKey as PublicKey
from dryoc._dryoc import kx_SessionKeys as SessionKeys
from dryoc._dryoc import kx_client_session_keys as client_session_keys
from dryoc._dryoc import kx_server_session_keys as server_session_keys

__all__ = ["KeyPair", "PublicKey", "SessionKeys", "client_session_keys", "server_session_keys"]
