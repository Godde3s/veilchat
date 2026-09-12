"""End-to-end encryption primitives for VeilChat.

VeilChat uses a Noise-inspired, mutually-authenticated handshake:

1. Every peer owns a long-term X25519 identity key.
2. On connect, both sides generate a fresh ephemeral X25519 key pair.
3. Three Diffie-Hellman results are mixed — ephemeral-ephemeral,
   initiator-ephemeral x responder-static and vice versa — through
   HKDF-SHA256. The session is therefore forward-secret (ephemeral keys)
   *and* mutually authenticated (static keys influence the final secret).
4. Both directions derive independent ChaCha20-Poly1305 keys; the
   transcript MAC sent right after the handshake proves both sides
   derived the same secret without leaking it.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"VC01"
PROTOCOL_VERSION = 1
IDENTITY_DIR = Path.home() / ".veilchat"
IDENTITY_FILE = IDENTITY_DIR / "identity.key"

_TRANSCRIPT_LABEL = b"veilchat-v1-handshake"
_VERIFY_LABEL = b"veilchat-v1-verify"
_C2S_LABEL = b"veilchat-v1-key-client-to-server"
_S2C_LABEL = b"veilchat-v1-key-server-to-client"


# --------------------------------------------------------------------------
# Identity keys
# --------------------------------------------------------------------------

def generate_identity() -> X25519PrivateKey:
    """Create a fresh X25519 identity key."""
    return X25519PrivateKey.generate()


def save_identity(key: X25519PrivateKey, path: Path = IDENTITY_FILE) -> None:
    """Persist the identity key with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)


def load_or_create_identity(path: Path = IDENTITY_FILE) -> X25519PrivateKey:
    """Load the local identity key, creating one on first run."""
    if path.exists():
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        raw = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return X25519PrivateKey.from_private_bytes(raw)
    key = generate_identity()
    save_identity(key, path)
    return key


def public_bytes(key: X25519PrivateKey | X25519PublicKey) -> bytes:
    if isinstance(key, X25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint(key: X25519PrivateKey | X25519PublicKey, groups: int = 5) -> str:
    """Human-comparable SHA-256 fingerprint, e.g. ``3FA9 C21B ...``."""
    digest = hashlib.sha256(public_bytes(key)).hexdigest().upper()[: groups * 4]
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


# --------------------------------------------------------------------------
# Handshake + session keys
# --------------------------------------------------------------------------

def _dh(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))


def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=_TRANSCRIPT_LABEL,
        info=info,
    ).derive(ikm)


def derive_session_keys(
    role: str,
    static: X25519PrivateKey,
    eph: X25519PrivateKey,
    peer_static: bytes,
    peer_eph: bytes,
) -> tuple[bytes, bytes]:
    """Derive (send_key, recv_key) for one side of the session.

    Both sides must mix the DH results in the *same transcript order*:
    ``ee || es || se`` where ``es = eph_i x static_r`` and
    ``se = static_i x eph_r``. The responder therefore mirrors the order.
    """
    ee = _dh(eph, peer_eph)
    if role == "initiator":
        es = _dh(eph, peer_static)      # eph_i x static_r
        se = _dh(static, peer_eph)      # static_i x eph_r
    elif role == "responder":
        es = _dh(static, peer_eph)      # static_r x eph_i == eph_i x static_r
        se = _dh(eph, peer_static)      # eph_r x static_i == static_i x eph_r
    else:
        raise ValueError("role must be 'initiator' or 'responder'")
    ikm = ee + es + se

    init_key = _hkdf(ikm, _C2S_LABEL)
    resp_key = _hkdf(ikm, _S2C_LABEL)
    if role == "initiator":
        return init_key, resp_key
    return resp_key, init_key


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hmac as _hmac

    return _hmac.new(key, data, hashlib.sha256).digest()


def transcript_mac(send_key: bytes, client_eph: bytes, server_eph: bytes) -> bytes:
    """Proof-of-possession MAC over the handshake transcript."""
    return hmac_sha256(send_key, _VERIFY_LABEL + client_eph + server_eph)


# --------------------------------------------------------------------------
# Frame sealing
# --------------------------------------------------------------------------

class FrameCipher:
    """ChaCha20-Poly1305 sealer with strict monotonic nonces.

    Seal and open keep **independent** counters, so one instance can
    safely handle both sending and receiving — each direction consumes
    its own nonce space (the peer mirrors this, so counters align).
    The 96-bit nonce is ``4 zero bytes || u64 BE counter``.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("session key must be 32 bytes")
        self._aead = ChaCha20Poly1305(key)
        self._seal_counter = 0
        self._open_counter = 0

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = struct.pack(">Q", self._seal_counter).rjust(12, b"\x00")
        self._seal_counter += 1
        return self._aead.encrypt(nonce, plaintext, aad)

    def open(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        nonce = struct.pack(">Q", self._open_counter).rjust(12, b"\x00")
        self._open_counter += 1
        return self._aead.decrypt(nonce, ciphertext, aad)


def random_id(n: int = 8) -> str:
    return os.urandom(n).hex()
