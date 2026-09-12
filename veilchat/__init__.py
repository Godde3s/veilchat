"""VeilChat — serverless P2P messenger with end-to-end encryption."""

from .crypto import (
    FrameCipher,
    derive_session_keys,
    fingerprint,
    load_or_create_identity,
)
from .protocol import ProtocolError
from .peer import Session, connect, listen

__version__ = "1.0.0"
__all__ = [
    "Session",
    "connect",
    "listen",
    "fingerprint",
    "load_or_create_identity",
    "derive_session_keys",
    "FrameCipher",
    "ProtocolError",
    "__version__",
]
