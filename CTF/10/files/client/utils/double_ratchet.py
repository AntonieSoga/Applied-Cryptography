"""
Double Ratchet Algorithm Implementation
Based on Signal Protocol specification: https://signal.org/docs/specifications/doubleratchet/
Uses cryptography library.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.x3dh import KeyPair, dh, generate_key_pair

MAX_SKIP = 100  # Max skipped messages before error
KDF_RK_INFO = b"RK-Derivative"
KDF_CK_INFO = b"CK-Derivative"


def default_kdf(*_args: bytes | str | None) -> tuple[bytes, bytes]:
    return os.urandom(32), os.urandom(32)


def default_rnd(*_args: bytes | str | None) -> bytes:
    return os.urandom(12)


def ENCRYPT(
    mk: bytes,
    plaintext: str,
    ad: bytes,
    nonce: bytes,
) -> tuple[bytes, bytes]:
    """AEAD encryption using AES-256-GCM.

    Returns:
        (nonce, ciphertext, tag)
    """
    aesgcm = AESGCM(mk)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode(), ad)

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, tag


def DECRYPT(
    mk: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    ad: bytes,
) -> str:
    """AEAD decryption using AES-256-GCM.

    Returns:
        Decrypted plaintext
    """
    aesgcm = AESGCM(mk)
    # Reconstruct the expected format: ciphertext + tag
    ciphertext_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, ad)
    return plaintext.decode()


@dataclass
class Header:
    """Message header containing ratchet information."""

    dh: bytes  # Public DH key
    pn: int  # Previous chain length
    n: int  # Current message number


def HEADER(dh_public: bytes, pn: int, n: int) -> Header:
    """Create a message header."""
    return Header(dh=dh_public, pn=pn, n=n)


def CONCAT(ad: bytes, header: Header) -> bytes:
    """Concatenate associated data with header."""
    # Encode header: dh (32) + pn (4) + n (4)
    header_bytes = (
        header.dh + header.pn.to_bytes(4, "big") + header.n.to_bytes(4, "big")
    )
    return ad + header_bytes


@dataclass
class RatchetState:
    """Double Ratchet state machine."""

    DHs: KeyPair  # Sending DH private key
    DHr: bytes | None = None  # Receiving DH public key
    RK: bytes | None = None  # Root key (32 bytes)
    CKs: bytes | None = None  # Sending chain key (32 bytes)
    CKr: bytes | None = None  # Receiving chain key (32 bytes)
    Ns: int = 0  # Sending message number
    Nr: int = 0  # Receiving message number
    PN: int = 0  # Previous chain length
    MKSKIPPED: dict[tuple[bytes, int], bytes] = field(
        default_factory=dict
    )  # Skipped message keys
    pending_x3dh: dict[str, bytes] | None = None
    nonce_gen: Callable[[bytes | None, str], bytes] = field(default=default_rnd)
    kdf_rk: Callable[[bytes, bytes], tuple[bytes, bytes]] = field(default=default_kdf)
    kdf_ck: Callable[[bytes | None], tuple[bytes, bytes]] = field(default=default_kdf)


def RatchetInitInitiator(
    SK: bytes,
    bob_dh_public_key: bytes,
    kdf_rk: Callable[[bytes, bytes], tuple[bytes, bytes]] = default_kdf,
    kdf_ck: Callable[[bytes | None], tuple[bytes, bytes]] = default_kdf,
    nonce_gen: Callable[[bytes | None, str], bytes] = default_rnd,
) -> RatchetState:
    """Initialize Alice's ratchet state (Alice sends first)."""
    alice_dh = generate_key_pair()
    dh_out = dh(
        alice_dh.private_key,
        x25519.X25519PublicKey.from_public_bytes(bob_dh_public_key),
    )
    rk, cks = kdf_rk(SK, dh_out)

    state = RatchetState(
        DHs=alice_dh,
        DHr=bob_dh_public_key,
        RK=rk,
        CKs=cks,
        CKr=None,
        Ns=0,
        Nr=0,
        PN=0,
        kdf_rk=kdf_rk,
        kdf_ck=kdf_ck,
        nonce_gen=nonce_gen,
    )
    return state


def RatchetInitResponder(
    SK: bytes,
    bob_dh: KeyPair,
    kdf_rk: Callable[[bytes, bytes], tuple[bytes, bytes]] = default_kdf,
    kdf_ck: Callable[[bytes | None], tuple[bytes, bytes]] = default_kdf,
    nonce_gen: Callable[[bytes | None, str], bytes] = default_rnd,
) -> RatchetState:
    """Initialize Bob's ratchet state (Bob receives first)."""
    state = RatchetState(
        DHs=bob_dh,
        DHr=None,
        RK=SK,
        CKs=None,
        CKr=None,
        Ns=0,
        Nr=0,
        PN=0,
        kdf_rk=kdf_rk,
        kdf_ck=kdf_ck,
        nonce_gen=nonce_gen,
    )
    return state


def RatchetSendKey(state: RatchetState) -> tuple[int, bytes]:
    """Derive next message key for sending."""
    if state.CKs is None:
        raise ValueError("Cannot send - CKs is None")
    state.CKs, mk = state.kdf_ck(state.CKs)
    ns = state.Ns
    state.Ns += 1
    return ns, mk


def RatchetEncrypt(
    state: RatchetState,
    plaintext: str,
    ad: bytes = b"",
) -> tuple[Header, bytes, bytes, bytes]:
    """Encrypt a message.

    Returns:
        (header, nonce, ciphertext, tag)
    """
    ns, mk = RatchetSendKey(state)
    header = HEADER(state.DHs.public_bytes(), state.PN, ns)

    nonce = state.nonce_gen(state.CKs, plaintext)

    ciphertext, tag = ENCRYPT(mk, plaintext, CONCAT(ad, header), nonce=nonce)

    return header, nonce, ciphertext, tag


def TrySkippedMessageKeys(state: RatchetState, header: Header) -> bytes | None:
    """Try to retrieve a skipped message key."""
    key = (header.dh, header.n)
    if key in state.MKSKIPPED:
        mk = state.MKSKIPPED[key]
        del state.MKSKIPPED[key]
        return mk
    return None


def SkipMessageKeys(state: RatchetState, until: int) -> None:
    """Skip message keys up to a certain message number."""
    if state.CKr is None:
        return

    if state.Nr + MAX_SKIP < until:
        raise ValueError(f"Too many skipped messages: {until - state.Nr}")

    while state.Nr < until:
        state.CKr, mk = state.kdf_ck(state.CKr)
        assert state.DHr is not None
        state.MKSKIPPED[(state.DHr, state.Nr)] = mk
        state.Nr += 1


def DHRatchet(state: RatchetState, header: Header) -> None:
    """Perform DH ratchet step."""
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh

    # Compute shared secret with peer's new public key
    dh_out = dh(
        state.DHs.private_key,
        x25519.X25519PublicKey.from_public_bytes(state.DHr),
    )
    assert state.RK is not None
    state.RK, state.CKr = state.kdf_rk(state.RK, dh_out)

    # Generate new ephemeral key pair
    state.DHs = generate_key_pair()

    # Compute shared secret with new private key
    dh_out = dh(
        state.DHs.private_key,
        x25519.X25519PublicKey.from_public_bytes(state.DHr),
    )
    state.RK, state.CKs = state.kdf_rk(state.RK, dh_out)


def RatchetReceiveKey(state: RatchetState, header: Header) -> bytes:
    """Derive message key for receiving."""
    mk = TrySkippedMessageKeys(state, header)
    if mk is not None:
        return mk

    if header.dh != state.DHr:
        SkipMessageKeys(state, header.pn)
        DHRatchet(state, header)

    SkipMessageKeys(state, header.n)
    state.CKr, mk = state.kdf_ck(state.CKr)
    state.Nr += 1
    return mk


def RatchetDecrypt(
    state: RatchetState,
    header: Header,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    ad: bytes = b"",
) -> str:
    """Decrypt a message."""
    mk = RatchetReceiveKey(state, header)
    return DECRYPT(mk, nonce, ciphertext, tag, CONCAT(ad, header))
