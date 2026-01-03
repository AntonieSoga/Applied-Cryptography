"""
X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol
Implementation based on Signal Protocol specification
https://signal.org/docs/specifications/x3dh/
"""

import base64
from typing import NamedTuple, TypedDict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"X3DH"


class KeyPair(NamedTuple):
    """Represents a Diffie-Hellman key pair."""

    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    def public_bytes(self) -> bytes:
        """Return raw public key bytes (32 bytes)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_bytes(self) -> bytes:
        """Return raw private key bytes (32 bytes)."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_bytes(cls, private_bytes: bytes) -> "KeyPair":
        """Reconstruct KeyPair from private bytes."""
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        return cls(private_key, public_key)


def generate_key_pair() -> KeyPair:
    """Generate a Curve25519 key pair."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(private_key=private_key, public_key=public_key)


def dh(sk: x25519.X25519PrivateKey, pk: x25519.X25519PublicKey) -> bytes:
    """
    Perform Diffie-Hellman operation. Computes shared secret from private
    key sk and public key pk.
    """
    return sk.exchange(pk)


class PreKeyBundleInitiator(TypedDict):
    """Prekey bundle structure for initiator (Alice)."""

    IK_a: bytes
    EK: bytes


class X3DHInitiator:
    """X3DH Initiator state and operations (Alice)."""

    def __init__(self, IK: KeyPair, EK: KeyPair) -> None:
        """Initialize with identity and ephemeral key pairs."""
        self.IK_a: KeyPair = IK
        self.EK_a: KeyPair = EK

    def get_prekey_bundle(self) -> PreKeyBundleInitiator:
        """
        Return Alice's prekey bundle to send to server.

        Contains:
          - IK_a
          - EK
        """
        return {
            "IK_a": self.IK_a.public_bytes(),
            "EK": self.EK_a.public_bytes(),
        }

    def compute_shared_secret(
        self,
        IK_b_bytes: bytes,
        SPK_b_bytes: bytes,
        OPK_b_bytes: bytes | None = None,
    ) -> bytes:
        """
        Compute shared secret using Bob's prekeys.

        X3DH protocol:

          DH1 = DH(IK_a, SPK_b)
          DH2 = DH(EK_a, IK_b)
          DH3 = DH(EK_a, SPK_b)
          DH4 = DH(EK_a, OPK_b)  # Optional

          SK = KDF(DH1 || DH2 || DH3 [|| DH4])
        """
        # Import Bob's public keys
        IK_b = x25519.X25519PublicKey.from_public_bytes(IK_b_bytes)
        SPK_b = x25519.X25519PublicKey.from_public_bytes(SPK_b_bytes)

        # Perform three DH operations
        DH1 = dh(self.IK_a.private_key, SPK_b)
        DH2 = dh(self.EK_a.private_key, IK_b)
        DH3 = dh(self.EK_a.private_key, SPK_b)

        # Optional: fourth DH with one-time key for additional security
        DH4 = (
            dh(
                self.EK_a.private_key,
                x25519.X25519PublicKey.from_public_bytes(OPK_b_bytes),
            )
            if OPK_b_bytes
            else b""
        )

        # Concatenate DH outputs
        dh_output = DH1 + DH2 + DH3 + DH4

        # Derive shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO,
        )
        shared_secret = hkdf.derive(dh_output)

        return shared_secret

    def to_dict(self) -> dict[str, str]:
        """Serialize identities to a dictionary (base64 encoded)."""
        ik_bytes = self.IK_a.private_bytes()
        ek_bytes = self.EK_a.private_bytes()

        return {
            "IK_private": base64.b64encode(ik_bytes).decode("utf-8"),
            "EK_private": base64.b64encode(ek_bytes).decode("utf-8"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "X3DHInitiator":
        """Reconstruct X3DHInitiator from serialized dictionary."""
        IK = KeyPair.from_bytes(base64.b64decode(data["IK_private"]))
        EK = KeyPair.from_bytes(base64.b64decode(data["EK_private"]))

        return cls(IK=IK, EK=EK)


class PreKeyBundleResponder(TypedDict):
    """Prekey bundle structure for responder (Bob)."""

    SIK_b: bytes
    IK_b: bytes
    SPK_b: bytes
    OPK_b: bytes
    Sig_IK: bytes
    Sig_SPK: bytes


class X3DHResponder:
    """X3DH Responder state and operations (Bob)."""

    def __init__(
        self,
        IK: KeyPair,
        SIK: ed25519.Ed25519PrivateKey,
        SPK: KeyPair,
        with_opk: bool = True,
    ) -> None:
        """Initialize with identity and prekeys.

        Generates:

            - SIK_b: Signing Identity Key (Ed25519)
            - IK_b: Long-term DH Identity Key (X25519)
            - SPK_b: Signed Prekey (medium-term DH key, signed with SIK)
            - OPK_b: (optional, if with_opk=True) One-time Prekey (X25519)
        """
        self.with_opk: bool = with_opk
        self.IK_b: KeyPair = IK
        self.SIK_b: ed25519.Ed25519PrivateKey = SIK
        self.SPK_b: KeyPair = SPK
        self.OPK_b: KeyPair | None = None

    def get_prekey_bundle(self) -> PreKeyBundleResponder:
        """
        Return Bob's prekey bundle for public distribution. Server stores these
        and gives them to clients requesting Bob's keys. A new one-time prekey
        should be generated and uploaded when this one is used.
        """
        self.OPK_b = generate_key_pair() if self.with_opk else None

        return {
            "SIK_b": (
                self.SIK_b.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
            "IK_b": self.IK_b.public_bytes(),
            "SPK_b": self.SPK_b.public_bytes(),
            "OPK_b": self.OPK_b.public_bytes() if self.OPK_b else b"",
            "Sig_IK": self.SIK_b.sign(self.IK_b.public_bytes()),
            "Sig_SPK": self.SIK_b.sign(self.SPK_b.public_bytes()),
        }

    def compute_shared_secret(
        self,
        IK_a_bytes: bytes,
        EK_a_bytes: bytes,
    ) -> bytes:
        """
        Compute shared secret using Alice's ephemeral key and identity.

        Same computation as initiator, but from responder's perspective:

        DH1 = DH(SPK_b, IK_a)
        DH2 = DH(IK_b, EK_a)
        DH3 = DH(SPK_b, EK_a)
        [DH4 = DH(OPK_b, EK_a)]

        SK = KDF(DH1 || DH2 || DH3 [|| DH4])
        """
        # Import Alice's public keys
        IK_a = x25519.X25519PublicKey.from_public_bytes(IK_a_bytes)
        EK_a = x25519.X25519PublicKey.from_public_bytes(EK_a_bytes)

        # Perform three DH operations
        DH1 = dh(self.SPK_b.private_key, IK_a)
        DH2 = dh(self.IK_b.private_key, EK_a)
        DH3 = dh(self.SPK_b.private_key, EK_a)
        DH4 = dh(self.OPK_b.private_key, EK_a) if self.OPK_b else b""

        # Concatenate DH outputs
        dh_output = DH1 + DH2 + DH3 + DH4

        # Derive shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO,
        )
        shared_secret = hkdf.derive(dh_output)

        return shared_secret

    def to_dict(self) -> dict[str, str]:
        """Serialize identities to a dictionary (base64 encoded)."""
        sik_bytes = self.SIK_b.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ik_bytes = self.IK_b.private_bytes()
        spk_bytes = self.SPK_b.private_bytes()

        return {
            "SIK_private": base64.b64encode(sik_bytes).decode("utf-8"),
            "IK_private": base64.b64encode(ik_bytes).decode("utf-8"),
            "SPK_private": base64.b64encode(spk_bytes).decode("utf-8"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "X3DHResponder":
        """Reconstruct X3DHResponder from serialized dictionary."""
        SIK = ed25519.Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(data["SIK_private"])
        )
        IK = KeyPair.from_bytes(base64.b64decode(data["IK_private"]))
        SPK = KeyPair.from_bytes(base64.b64decode(data["SPK_private"]))

        return cls(IK=IK, SIK=SIK, SPK=SPK, with_opk=True)
