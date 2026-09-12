"""Cryptographic core tests — the part that must never be wrong."""

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from veilchat.crypto import (
    FrameCipher,
    derive_session_keys,
    fingerprint,
    generate_identity,
    public_bytes,
    transcript_mac,
)


def _pair():
    a, b = generate_identity(), generate_identity()
    return a, b


def test_session_keys_match_and_are_directional():
    a_static, b_static = _pair()
    a_eph, b_eph = _pair()

    a_send, a_recv = derive_session_keys(
        "initiator", a_static, a_eph,
        public_bytes(b_static), public_bytes(b_eph),
    )
    b_send, b_recv = derive_session_keys(
        "responder", b_static, b_eph,
        public_bytes(a_static), public_bytes(a_eph),
    )

    assert a_send == b_recv          # initiator→responder key agrees
    assert a_recv == b_send          # responder→initiator key agrees
    assert a_send != a_recv          # directions are separated


def test_session_keys_depend_on_every_dh_component():
    a_static, b_static = _pair()
    a_eph, b_eph = _pair()

    k1 = derive_session_keys("initiator", a_static, a_eph,
                             public_bytes(b_static), public_bytes(b_eph))
    k2 = derive_session_keys("initiator", a_static, a_eph,
                             public_bytes(b_static), public_bytes(b_eph))
    assert k1 == k2                  # deterministic

    c_eph = generate_identity()
    k3 = derive_session_keys("initiator", a_static, c_eph,
                             public_bytes(b_static), public_bytes(b_eph))
    assert k1[0] != k3[0]            # fresh ephemeral → fresh keys


def test_frame_cipher_roundtrip_and_tamper_detection():
    key = derive_session_keys(
        "initiator", *_pair(), public_bytes(generate_identity()),
        public_bytes(generate_identity()),
    )[0]
    cipher = FrameCipher(key)

    ct = cipher.seal(b"hello veil")
    assert cipher.open(ct) == b"hello veil"

    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(Exception):
        cipher.open(bytes(tampered))


def test_nonce_never_reuses():
    key = b"\x01" * 32
    c1, c2 = FrameCipher(key), FrameCipher(key)
    first = c1.seal(b"a")
    second = c1.seal(b"a")
    assert first != second           # same plaintext, different nonce
    assert c2.open(first) == b"a"    # fresh cipher counter aligns


def test_fingerprint_is_stable_and_readable():
    a, _ = _pair()
    fp1, fp2 = fingerprint(a), fingerprint(a)
    assert fp1 == fp2
    assert len(fp1.split()) == 5
    assert all(len(g) == 4 for g in fp1.split())
    assert fingerprint(a) != fingerprint(generate_identity())


def test_transcript_mac_binds_ephemerals():
    a, _ = _pair()
    key = b"\x02" * 32
    e1, e2 = public_bytes(generate_identity()), public_bytes(generate_identity())
    assert transcript_mac(key, e1, e2) == transcript_mac(key, e1, e2)
    assert transcript_mac(key, e1, e2) != transcript_mac(key, e2, e1)
