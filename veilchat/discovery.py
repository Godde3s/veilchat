"""LAN peer discovery over UDP broadcast.

A listening peer announces itself with a small signed-ish beacon (the
fingerprint lets the other side verify *who* it found before connecting).
Discovery is optional — direct `connect` works without it.
"""

from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass

DISCOVERY_PORT = 53127
BEACON_MAGIC = "veilchat-beacon/1"


@dataclass(frozen=True)
class DiscoveredPeer:
    name: str
    host: str
    port: int
    fingerprint: str


async def announce(port: int, name: str, fp: str, interval: float = 3.0) -> None:
    """Broadcast our presence every ``interval`` seconds (run as a task)."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)

    beacon = json.dumps({
        "magic": BEACON_MAGIC,
        "name": name,
        "port": port,
        "fp": fp,
    }).encode()

    while True:
        try:
            await loop.sock_sendto(sock, beacon, ("255.255.255.255", DISCOVERY_PORT))
        except OSError:
            pass
        await asyncio.sleep(interval)


async def discover(timeout: float = 4.0) -> list[DiscoveredPeer]:
    """Listen for beacons for ``timeout`` seconds, return unique peers."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except OSError:
        return []
    sock.setblocking(False)

    found: dict[str, DiscoveredPeer] = {}

    async def _drain() -> None:
        while True:
            data, addr = await loop.sock_recvfrom(sock, 2048)
            try:
                payload = json.loads(data.decode())
                if payload.get("magic") != BEACON_MAGIC:
                    continue
                peer = DiscoveredPeer(
                    name=payload.get("name", "unknown"),
                    host=addr[0],
                    port=int(payload.get("port", 0)),
                    fingerprint=payload.get("fp", ""),
                )
                found[peer.fingerprint or peer.host] = peer
            except (ValueError, UnicodeDecodeError):
                continue

    task = asyncio.ensure_future(_drain())
    await asyncio.sleep(timeout)
    task.cancel()
    sock.close()
    return sorted(found.values(), key=lambda p: p.name)
