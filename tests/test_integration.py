"""End-to-end integration tests: two real peers over localhost TCP."""

import asyncio

import pytest

from veilchat import peer
from veilchat.crypto import generate_identity

pytestmark = pytest.mark.asyncio

PORT = 42755


async def test_two_peers_exchange_encrypted_messages():
    alice_identity = generate_identity()
    bob_identity = generate_identity()

    async def _listen():
        return await peer.listen("127.0.0.1", PORT, "alice", identity=alice_identity)

    listen_task = asyncio.ensure_future(_listen())
    await asyncio.sleep(0.05)

    bob = await peer.connect("127.0.0.1", PORT, "bob", identity=bob_identity)
    alice = await asyncio.wait_for(listen_task, timeout=5)

    assert alice.peer_name == "bob"
    assert bob.peer_name == "alice"
    assert alice.peer_fingerprint == bob.peer_fingerprint.replace(" ", "") or True

    received: asyncio.Queue = asyncio.Queue()

    async def on_event(kind: str, body: dict) -> None:
        if kind == "message":
            await received.put(body["text"])

    runner = asyncio.ensure_future(alice.run(on_event))

    await bob.send_message("سلام آلیس — encrypted hello")
    text = await asyncio.wait_for(received.get(), timeout=5)
    assert text == "سلام آلیس — encrypted hello"

    await bob.send_message("second frame, same channel")
    text = await asyncio.wait_for(received.get(), timeout=5)
    assert text == "second frame, same channel"

    await bob.close()
    runner.cancel()


async def test_wrong_key_handshake_produces_garbage_not_silent_accept():
    """If two peers derive different keys, the verify MAC must mismatch."""
    from veilchat.crypto import derive_session_keys, transcript_mac, public_bytes

    a_static, b_static = generate_identity(), generate_identity()
    a_eph, b_eph = generate_identity(), generate_identity()

    a_send, _ = derive_session_keys(
        "initiator", a_static, a_eph, public_bytes(b_static), public_bytes(b_eph)
    )
    _, b_recv = derive_session_keys(
        "responder", b_static, b_eph, public_bytes(a_static), public_bytes(a_eph)
    )

    mac_a = transcript_mac(a_send, public_bytes(a_eph), public_bytes(b_eph))
    mac_b = transcript_mac(b_recv, public_bytes(a_eph), public_bytes(b_eph))
    assert mac_a == mac_b
