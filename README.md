# VeilChat

<p align="center">
  <strong>Serverless P2P messenger with end-to-end encryption.<br>
  No accounts. No servers. No phone numbers. No metadata.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#how-the-encryption-works">Crypto Design</a> ·
  <a href="#cli">CLI</a> ·
  <a href="#library-usage">Library</a>
</p>

---

## Why VeilChat

Every mainstream messenger quietly relies on infrastructure that knows
*who* talks to *whom*, even when it cannot read the content. VeilChat
removes that infrastructure entirely: two peers open a **direct TCP
connection**, run a **mutually-authenticated key exchange**, and talk over
an **encrypted channel** that never touches a third party.

It is a deliberate exercise in building the hard parts of a messenger —
key management, handshake design, wire protocol, NAT-friendly delivery —
in ~1,000 lines of readable, auditable Python.

```
┌──────────────┐        direct TCP (or LAN discovery)       ┌──────────────┐
│   Peer A     │  ── X25519 handshake ── ChaCha20 frames ── │   Peer B     │
│ identity key │      transcript MAC verification           │ identity key │
└──────────────┘                                            └──────────────┘
```

## Quick Start

```bash
pip install veilchat

# terminal 1 — announce yourself on the LAN and wait
veilchat listen --name alice

# terminal 2 (or another machine) — find alice and connect
veilchat lan
veilchat connect 192.168.1.20 --name bob
```

Verify each other's fingerprint out-of-band once, and every future
session is authenticated:

```bash
veilchat fingerprint
# VeilChat identity fingerprint:
#   3FA9 C21B 88D0 47E2 A1C6
```

## How the Encryption Works

VeilChat implements a Noise-inspired handshake — not a homemade cipher,
just standard primitives arranged carefully:

1. **Long-term identity** — every peer owns an X25519 identity key stored
   at `~/.veilchat/identity.key` (mode `0600`). Its SHA-256 fingerprint
   is what humans compare out-of-band.
2. **Ephemeral exchange** — each connection generates fresh X25519
   ephemeral keys. Three DH results are mixed: `ee`, `es`, `se`.
3. **Key derivation** — HKDF-SHA256 expands the mixed secret into two
   *directional* session keys, so each direction encrypts under its own
   key and nonce space.
4. **Mutual authentication** — both sides exchange a transcript MAC that
   only someone holding the shared secret can compute. A man in the
   middle cannot produce it because `es`/`se` bind the static identities.
5. **Frame sealing** — every application frame is sealed with
   ChaCha20-Poly1305 under a monotonically increasing 96-bit nonce and
   direction-bound AAD, blocking replay into the opposite direction.
6. **Flood protection** — 4 MiB hard cap on any single frame.

Forward secrecy: compromising the identity key later does not decrypt
past sessions, because every session mixed in fresh ephemeral keys.

## CLI

| Command | Purpose |
| --- | --- |
| `veilchat fingerprint` | Print your identity fingerprint |
| `veilchat listen --port N` | Wait for a peer, then chat |
| `veilchat connect HOST [PORT]` | Connect to a peer, then chat |
| `veilchat lan` | Discover listening peers via UDP beacon |

In-chat commands: `/typing`, `/quit`.

## Library Usage

```python
import asyncio
from veilchat import connect

async def main():
    session = await connect("10.0.0.7", 42740, "my-name")

    async def on_event(kind, body):
        if kind == "message":
            print(f"{session.peer_name}: {body['text']}")

    await session.send_message("hello over an encrypted channel")
    await session.run(on_event)

asyncio.run(main())
```

The transport, handshake and framing layers are fully separated — swap
TCP for WebRTC data channels or a relay without touching the crypto.

## Project Layout

```
veilchat/
├── veilchat/
│   ├── crypto.py        # identity, handshake, HKDF, AEAD (audit this first)
│   ├── protocol.py      # wire format: handshake + sealed frames
│   ├── peer.py          # asyncio session layer
│   ├── discovery.py     # UDP LAN beacons
│   └── cli.py           # argparse CLI
└── tests/               # unit + integration (two live peers on localhost)
```

## Roadmap

- [ ] TCP relay fallback for hard NATs
- [ ] Group chats (star topology over pairwise channels)
- [ ] Offline messages via optional encrypted drop-boxes
- [ ] File transfer UI on top of the existing file frames

## License

MIT © Reza Bazdar (Godde3s)
