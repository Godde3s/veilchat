"""Wire protocol for VeilChat.

Layout is intentionally simple and audit-friendly:

* Handshake frames: ``MAGIC(4) || version(1) || u32 length || JSON body``
* Sealed frames:    ``u32 length || ChaCha20-Poly1305 ciphertext``
  where the decrypted plaintext is ``type(1) || JSON body``.

Every sealed frame is bound to a direction label (AAD) so a captured
frame cannot be replayed into the opposite direction.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Any

from .crypto import MAGIC, FrameCipher, PROTOCOL_VERSION

# Handshake message types (plaintext JSON, pre-encryption)
HELLO = "hello"          # both sides: identity + ephemeral public keys
VERIFY = "verify"        # both sides: transcript MAC
READY = "ready"          # final ack, sent by responder

# Sealed application frame types (first byte of plaintext)
T_MSG = 0x01             # chat message: {"t":1,"text":"...","ts":...}
T_TYPING = 0x02          # typing indicator: {"t":2,"on":true}
T_PING = 0x03            # liveness probe
T_FILE_OFFER = 0x04      # {"t":4,"name":"...","size":123}
T_FILE_CHUNK = 0x05      # {"t":5,"id":"...","seq":0,"data":"b64"}
T_CLOSE = 0x06           # graceful goodbye

# Handshake-adjacent sealed frames (AAD = b"verify")
T_VERIFY = 0x10          # transcript MAC exchange
T_READY = 0x11           # final ack, sent by responder

MAX_FRAME = 4 * 1024 * 1024  # 4 MiB hard cap, defends against floods


class ProtocolError(Exception):
    """Raised when a peer violates the wire protocol."""


@dataclass
class HandshakeState:
    role: str                                # "initiator" | "responder"
    our_static: bytes = b""
    our_ephemeral: bytes = b""
    peer_static: bytes = b""
    peer_ephemeral: bytes = b""
    extra: dict[str, Any] = field(default_factory=dict)

    def hello_payload(self, display_name: str) -> dict[str, Any]:
        return {
            "v": PROTOCOL_VERSION,
            "static": self.our_static.hex(),
            "ephemeral": self.our_ephemeral.hex(),
            "name": display_name,
        }

    def apply_hello(self, payload: dict[str, Any]) -> str:
        if payload.get("v") != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version {payload.get('v')}")
        self.peer_static = bytes.fromhex(payload["static"])
        self.peer_ephemeral = bytes.fromhex(payload["ephemeral"])
        return str(payload.get("name", "peer"))


def encode_handshake(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode()
    if len(body) > MAX_FRAME:
        raise ProtocolError("handshake payload too large")
    return MAGIC + struct.pack(">BI", PROTOCOL_VERSION, len(body)) + body


async def read_handshake(reader) -> dict[str, Any]:
    magic = await reader.readexactly(len(MAGIC))
    if magic != MAGIC:
        raise ProtocolError("not a VeilChat handshake")
    version, length = struct.unpack(">BI", await reader.readexactly(5))
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version {version}")
    if length > MAX_FRAME:
        raise ProtocolError("handshake frame too large")
    body = await reader.readexactly(length)
    return json.loads(body)


async def write_handshake(writer, payload: dict[str, Any]) -> None:
    writer.write(encode_handshake(payload))
    await writer.drain()


async def write_sealed(writer, cipher: FrameCipher, frame_type: int,
                       payload: dict[str, Any], aad: bytes) -> None:
    plaintext = bytes([frame_type]) + json.dumps(payload, separators=(",", ":")).encode()
    ct = cipher.seal(plaintext, aad)
    if len(ct) > MAX_FRAME:
        raise ProtocolError("frame too large")
    writer.write(struct.pack(">I", len(ct)) + ct)
    await writer.drain()


async def read_sealed(reader, cipher: FrameCipher, aad: bytes) -> tuple[int, dict[str, Any]]:
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    if length > MAX_FRAME:
        raise ProtocolError("sealed frame too large")
    ct = await reader.readexactly(length)
    plaintext = cipher.open(ct, aad)
    frame_type = plaintext[0]
    body = json.loads(plaintext[1:].decode() or "{}")
    return frame_type, body


def frame_aad() -> bytes:
    """Symmetric AAD binding every sealed frame to the VeilChat protocol.

    Directional separation comes from the independent per-direction
    session keys, so the AAD only needs to be a shared channel label —
    both peers must seal and open with the *same* bytes.
    """
    return b"veilchat-v1-frame"
