"""Async peer-to-peer session layer for VeilChat.

``Session`` owns one encrypted connection: it runs the handshake,
verifies the transcript MAC, then multiplexes sealed application frames
to callbacks. Both ``listen()`` (responder) and ``connect()`` (initiator)
return a ready ``Session`` — everything above this layer never touches
sockets or keys directly.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from . import protocol as proto
from .crypto import (
    FrameCipher,
    derive_session_keys,
    fingerprint,
    load_or_create_identity,
    public_bytes,
    transcript_mac,
    generate_identity,
)

log = logging.getLogger("veilchat")

EventHandler = Callable[[str, dict], Awaitable[None]]


@dataclass
class Session:
    role: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    display_name: str
    peer_name: str
    send_cipher: FrameCipher
    recv_cipher: FrameCipher
    peer_fingerprint: str
    _tasks: set = field(default_factory=set)

    # -- outbound API ------------------------------------------------------

    async def send_message(self, text: str) -> None:
        await proto.write_sealed(
            self.writer, self.send_cipher, proto.T_MSG,
            {"text": text, "ts": int(time.time())},
            proto.frame_aad(),
        )

    async def send_typing(self, on: bool = True) -> None:
        await proto.write_sealed(
            self.writer, self.send_cipher, proto.T_TYPING,
            {"on": on}, proto.frame_aad(),
        )

    async def send_ping(self) -> None:
        await proto.write_sealed(
            self.writer, self.send_cipher, proto.T_PING,
            {"ts": int(time.time())}, proto.frame_aad(),
        )

    async def close(self) -> None:
        try:
            await proto.write_sealed(
                self.writer, self.send_cipher, proto.T_CLOSE,
                {}, proto.frame_aad(),
            )
        except Exception:
            pass
        self.writer.close()

    # -- inbound loop ------------------------------------------------------

    async def run(self, on_event: EventHandler) -> None:
        aad = proto.frame_aad()
        try:
            while True:
                frame_type, body = await proto.read_sealed(
                    self.reader, self.recv_cipher, aad
                )
                if frame_type == proto.T_MSG:
                    await on_event("message", body)
                elif frame_type == proto.T_TYPING:
                    await on_event("typing", body)
                elif frame_type == proto.T_PING:
                    await self.send_ping()
                    await on_event("ping", body)
                elif frame_type == proto.T_CLOSE:
                    await on_event("close", body)
                    break
                else:
                    log.debug("ignoring frame type %s", frame_type)
        except (asyncio.IncompleteReadError, ConnectionError):
            await on_event("close", {"reason": "disconnected"})
        finally:
            self.writer.close()


async def _run_handshake(
    role: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    display_name: str,
    identity=None,
) -> Session:
    identity = identity or load_or_create_identity()
    ephemeral = generate_identity()

    state = proto.HandshakeState(
        role=role,
        our_static=public_bytes(identity),
        our_ephemeral=public_bytes(ephemeral),
    )

    await proto.write_handshake(writer, state.hello_payload(display_name))
    peer_name = state.apply_hello(await proto.read_handshake(reader))

    send_key, recv_key = derive_session_keys(
        role, identity, ephemeral, state.peer_static, state.peer_ephemeral,
    )
    send_cipher, recv_cipher = FrameCipher(send_key), FrameCipher(recv_key)

    mac = transcript_mac(send_key, state.our_ephemeral, state.peer_ephemeral)
    await proto.write_sealed(writer, send_cipher, proto.T_VERIFY, {"mac": mac.hex()}, b"verify")
    frame, _body = await proto.read_sealed(reader, recv_cipher, b"verify")
    if frame != proto.T_VERIFY:
        raise proto.ProtocolError("expected verify frame")

    # Responders finish the handshake with a final READY ack.
    if role == "responder":
        await proto.write_sealed(writer, send_cipher, proto.T_READY, {"ok": True}, b"verify")
    else:
        frame, _ = await proto.read_sealed(reader, recv_cipher, b"verify")
        if frame != proto.T_READY:
            raise proto.ProtocolError("expected ready frame")

    peer_fp = fingerprint_from_bytes(state.peer_static)
    log.info("secure channel ready with %s (%s)", peer_name, peer_fp)

    return Session(
        role=role,
        reader=reader,
        writer=writer,
        display_name=display_name,
        peer_name=peer_name,
        send_cipher=send_cipher,
        recv_cipher=recv_cipher,
        peer_fingerprint=peer_fp,
    )


def fingerprint_from_bytes(static_pub: bytes) -> str:
    import hashlib

    digest = hashlib.sha256(static_pub).hexdigest().upper()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


async def listen(host: str, port: int, display_name: str, identity=None) -> Session:
    """Wait for one incoming VeilChat connection and secure it."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()

    async def _accept(reader, writer):
        if fut.done():                      # one session at a time
            writer.close()
            return
        session = await _run_handshake("responder", reader, writer, display_name, identity)
        fut.set_result(session)

    server = await asyncio.start_server(_accept, host, port)
    try:
        return await fut
    finally:
        server.close()          # stop accepting; existing session stays open


async def connect(host: str, port: int, display_name: str, identity=None) -> Session:
    """Connect to a listening VeilChat peer and secure the channel."""
    reader, writer = await asyncio.open_connection(host, port)
    return await _run_handshake("initiator", reader, writer, display_name, identity)
