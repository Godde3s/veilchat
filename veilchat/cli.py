"""VeilChat command line interface.

    veilchat fingerprint             show your identity fingerprint
    veilchat listen [--port N]       wait for a peer and chat
    veilchat connect HOST [PORT]     connect to a peer and chat
    veilchat lan                     discover peers on the local network
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from . import __version__, discovery, peer
from .crypto import fingerprint, load_or_create_identity


def _print_line(peer_name: str, text: str) -> None:
    print(f"\r\033[2K  {peer_name} › {text}")
    print("  you › ", end="", flush=True)


async def _chat(session: peer.Session) -> None:
    print(f"\n🔒 Secure channel established with {session.peer_name}")
    print(f"   their fingerprint: {session.peer_fingerprint}")
    print("   type a message and press Enter · /typing · /quit\n")

    loop = asyncio.get_running_loop()

    async def on_event(kind: str, body: dict) -> None:
        if kind == "message":
            _print_line(session.peer_name, body.get("text", ""))
        elif kind == "typing":
            if body.get("on"):
                _print_line(session.peer_name, "… is typing")
        elif kind == "close":
            print(f"\n← {session.peer_name} left the chat")

    reader_task = asyncio.ensure_future(session.run(on_event))

    while not reader_task.done():
        line = await loop.run_in_executor(None, sys.stdin.readline)
        line = line.rstrip("\n")
        if not line:
            continue
        if line == "/quit":
            await session.close()
            break
        if line == "/typing":
            await session.send_typing()
            continue
        print("  you › ", end="", flush=True)
        await session.send_message(line)

    reader_task.cancel()


def cmd_fingerprint(_args) -> int:
    identity = load_or_create_identity()
    print(f"VeilChat identity fingerprint:\n  {fingerprint(identity)}")
    print("\nCompare this out-of-band (in person, voice call) before trusting a peer.")
    return 0


def cmd_listen(args) -> int:
    name = args.name or getpass.getuser()

    async def _run() -> None:
        if not args.no_announce:
            identity = load_or_create_identity()
            asyncio.ensure_future(
                discovery.announce(args.port, name, fingerprint(identity))
            )
        print(f"VeilChat {__version__} — listening on 0.0.0.0:{args.port} as '{name}'")
        session = await peer.listen("0.0.0.0", args.port, name)
        await _chat(session)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    return 0


def cmd_connect(args) -> int:
    name = args.name or getpass.getuser()

    async def _run() -> None:
        print(f"VeilChat {__version__} — connecting to {args.host}:{args.port} …")
        session = await peer.connect(args.host, args.port, name)
        await _chat(session)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    except (ConnectionRefusedError, OSError) as exc:
        print(f"connection failed: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_lan(_args) -> int:
    async def _run() -> list:
        print("Scanning the local network for VeilChat peers …")
        return await discovery.discover()

    peers = asyncio.run(_run())
    if not peers:
        print("No peers found. Make sure the other side is running `veilchat listen`.")
        return 1
    print(f"Found {len(peers)} peer(s):")
    for p in peers:
        print(f"  • {p.name:<16} {p.host}:{p.port}  [{p.fingerprint}]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veilchat",
        description="Serverless P2P messenger with end-to-end encryption.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fingerprint", help="show your identity fingerprint")
    p.set_defaults(fn=cmd_fingerprint)

    p = sub.add_parser("listen", help="wait for a peer and chat")
    p.add_argument("--port", type=int, default=42740)
    p.add_argument("--name", help="display name (defaults to your OS user)")
    p.add_argument("--no-announce", action="store_true", help="disable LAN beacon")
    p.set_defaults(fn=cmd_listen)

    p = sub.add_parser("connect", help="connect to a peer and chat")
    p.add_argument("host")
    p.add_argument("port", type=int, nargs="?", default=42740)
    p.add_argument("--name", help="display name (defaults to your OS user)")
    p.set_defaults(fn=cmd_connect)

    p = sub.add_parser("lan", help="discover peers on the local network")
    p.set_defaults(fn=cmd_lan)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.fn(args))


if __name__ == "__main__":
    main()
