"""
This is a modified version of the clients used by the bots. Check the
`NOTE: (diff)` comments for differences. Rest of the code is identical.
"""

import hashlib
import json
import os
import queue
import socket
import sys
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from utils.conn import Message, Payload, b64dec, b64enc, recv_msg, send_msg
from utils.double_ratchet import (
    Header,
    RatchetDecrypt,
    RatchetEncrypt,
    RatchetInitInitiator,
    RatchetInitResponder,
    RatchetState,
)
from utils.x3dh import X3DHInitiator, X3DHResponder, generate_key_pair

# Configuration
IDENTITY_DIR = "identities"
HOST = "141.85.224.115"
PORT = 7206


def nonce_gen(_ck: bytes | None, plaintext: str) -> bytes:
    """Nonce generation."""
    return hashlib.sha256(plaintext.encode("utf-8")).digest()[:12]


def expand_seed(seed_bytes: bytes) -> bytes:
    """Expands a seed into 32 bytes."""
    seed_int = int.from_bytes(seed_bytes, "big")
    output = b""
    counter = 0
    while len(output) < 32:
        val = (seed_int + counter) % (2**24)
        output += val.to_bytes(3, "big")
        counter += 1
    return output[:32]


def KDF_RK(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Key Derivation Function for Root Key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"",
        info=b"",
    )
    key_material = hkdf.derive(rk + dh_out)
    rk, ck = key_material[:32], key_material[32:64]
    ck = expand_seed(ck[:3])

    return rk, ck


def KDF_CK(ck: bytes | None) -> tuple[bytes, bytes]:
    """Chain KDF."""
    if ck is None:
        raise ValueError("Chain key cannot be None")

    ck_int = int.from_bytes(ck, "big")
    next_ck_int = (ck_int + 1) % (2**256)

    next_ck = next_ck_int.to_bytes(32, "big")

    mk = next_ck

    return next_ck, mk


class ChatClient:
    def __init__(self, username: str, sock: socket.socket | None = None) -> None:
        self.username: str = username
        if sock:
            self.sock: socket.socket = sock
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sessions: dict[str, RatchetState] = {}
        self.peers: set[str] = set()
        self.msg_queue: queue.Queue[Message] = queue.Queue()
        self.running: bool = True
        self.x3dh_responder: X3DHResponder | None = None
        self.server_public_key: ed25519.Ed25519PublicKey | None = None

        self.load_client_identity()
        self.load_server_public_key()

    def load_client_identity(self) -> None:
        """Load or generate the client's X3DH identity."""
        identity_file = os.path.join(IDENTITY_DIR, f"{self.username.lower()}.json")

        if os.path.exists(identity_file):
            print(f"[*] Loading identity for {self.username} from {identity_file}")
            with open(identity_file, "r") as f:
                identity_data: dict[str, str] = json.load(f)

            self.x3dh_responder = X3DHResponder.from_dict(identity_data)
        else:
            print(
                f"[*] No identity found for user {self.username}. Generating new identity."
            )
            self.x3dh_responder = X3DHResponder(
                IK=generate_key_pair(),
                SIK=ed25519.Ed25519PrivateKey.generate(),
                SPK=generate_key_pair(),
                with_opk=True,
            )

    def load_server_public_key(self) -> None:
        """Load the server's public key for signature verification."""
        server_key_path = os.path.join(IDENTITY_DIR, "server_public.json")

        if os.path.exists(server_key_path):
            with open(server_key_path, "r") as f:
                data = json.load(f)
                pub_bytes = b64dec(data["public_key"])
                self.server_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    pub_bytes
                )
            print("[*] Loaded Server Public Key.")
        else:
            print(
                "[!] Warning: No Server Public Key found. Server authentication disabled."
            )

    def verify_server_message(self, msg: Message) -> bool:
        """Verify the server's signature on the message."""
        if self.server_public_key is None:
            # If we don't have a key, we can't verify.
            # NOTE: (diff) Clients refuse here to accept unauthenticated messages.
            return True

        # Check if message has a signature
        if "server_sig" not in msg:
            print(
                f"[!] Security Warning: Unsigned message from server: {msg.get('type')}"
            )
            return False

        signature = b64dec(msg["server_sig"])

        # Reconstruct canonical content
        content = msg.copy()
        del content["server_sig"]
        canonical_bytes = json.dumps(content, sort_keys=True).encode("utf-8")

        try:
            self.server_public_key.verify(signature, canonical_bytes)
            return True
        except Exception as e:
            print(f"[!] SECURITY ALERT: Server signature verification failed! {e}")
            return False

    def connect(self) -> None:
        try:
            try:
                self.sock.getpeername()
                # Already connected
            except OSError:
                self.sock.connect((HOST, PORT))

            bundle_json = {}
            if self.x3dh_responder:
                bundle_raw = self.x3dh_responder.get_prekey_bundle()
                bundle_json = {k: b64enc(bundle_raw[k]) for k in bundle_raw}

            send_msg(
                self.sock,
                {
                    "type": "REGISTER",
                    "username": self.username,
                    "bundle": bundle_json,
                },
            )

            threading.Thread(target=self.listen_loop, daemon=True).start()

        except Exception as e:
            print(f"Connection failed: {e}")
            sys.exit(1)

    def disconnect(self) -> None:
        self.running = False
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def listen_loop(self) -> None:
        while self.running:
            msg = recv_msg(self.sock)
            if not msg:
                print("\n[!] Disconnected from server.")
                self.running = False
                break

            self.handle_message(msg)

    def handle_message(self, msg: Message) -> None:
        msg_type = msg.get("type")

        if not self.verify_server_message(msg):
            print(f"[!] Dropping unauthenticated message: {msg_type}")
            return

        if msg_type == "REGISTER_SUCCESS":
            users = msg.get("users", [])
            print(f"[+] Connected as {self.username}")
            print(f"[+] Online users: {', '.join(users)}")

            # Update peers list (excluding self)
            for u in users:
                if u != self.username:
                    self.peers.add(u)

        elif msg_type == "USER_JOINED":
            new_user = msg.get("username")
            if new_user != self.username and new_user is not None:
                print(f"\n[+] {new_user} joined the chat")
                self.peers.add(new_user)

        elif msg_type == "USER_LEFT":
            left_user = msg.get("username")
            if left_user in self.peers:
                print(f"\n[-] {left_user} left the chat")
                self.peers.remove(left_user)

        elif msg_type == "MESSAGE":
            sender = msg.get("sender")
            if sender is None:
                print(f"\n[!] Empty sender from message")
                return
            payload = msg.get("payload")
            if payload is None:
                print(f"\n[!] Empty payload from {sender}")
                return
            self.decrypt_and_print(sender, payload)

        elif msg_type == "BUNDLE":
            self.msg_queue.put(msg)

        elif msg_type == "ERROR":
            err_msg = msg.get("message", "unknown error")
            print(f"\n[!] Server Error: {err_msg}")

    def get_bundle(self, target_user: str) -> dict[str, str] | None:
        """Request bundle and wait for response"""
        send_msg(self.sock, {"type": "FETCH_BUNDLE", "username": target_user})

        while True:
            resp = self.msg_queue.get(timeout=5)
            if resp.get("type") == "BUNDLE" and resp.get("username") == target_user:
                return resp.get("bundle")

    def decrypt_and_print(self, sender: str, payload: Payload) -> None:
        try:
            # Filter messages intended for others (Client-side filtering for Broadcast server)
            recipient = payload.get("recipient")
            if recipient is not None and recipient != self.username:
                # NOTE: (diff) We print here the intercepted messages.
                print(
                    f"\n[INTERCEPTED] Message from {sender} to {recipient}: {payload}"
                )
                return

            ptype = payload.get("type")
            ciphertext = b64dec(payload["ciphertext"])
            nonce = b64dec(payload["nonce"])
            tag = b64dec(payload["tag"])

            header_dict = payload["header"]
            header = Header(
                dh=b64dec(header_dict["dh"]),
                pn=header_dict["pn"],
                n=header_dict["n"],
            )

            # Check if this is a new session initialization
            if ptype == "INITIAL":
                if self.x3dh_responder is None:
                    print(
                        f"\n[!] No identity for {self.username}. Cannot establish session."
                    )
                    return

                ik_a = payload.get("ik_a")
                ek_a = payload.get("ek_a")
                if ik_a is None or ek_a is None:
                    print(
                        f"\n[!] No identity keys for {self.username}. Cannot establish session."
                    )
                    return

                # Verify sender's identity before accepting session
                if not self.verify_initiator_identity(sender, b64dec(ik_a)):
                    return

                sk = self.x3dh_responder.compute_shared_secret(
                    b64dec(ik_a),
                    b64dec(ek_a),
                )
                state = RatchetInitResponder(
                    sk,
                    self.x3dh_responder.SPK_b,
                    kdf_rk=KDF_RK,
                    kdf_ck=KDF_CK,
                    nonce_gen=nonce_gen,
                )
                self.sessions[sender] = state
                self.peers.add(sender)  # Ensure sender is in peers

            if sender not in self.sessions:
                print(f"\n[!] Received message from {sender} but no session exists.")
                return

            state = self.sessions[sender]
            plaintext = RatchetDecrypt(state, header, nonce, ciphertext, tag)
            self.on_decrypted_message(sender, plaintext)

        except InvalidTag:
            print(
                f"\n[!] Decryption failed from {sender}: InvalidTag (message likely not for us)"
            )
        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"\n[!] Decryption failed from {sender}: {e}")

    def on_decrypted_message(self, sender: str, plaintext: str) -> None:
        """Callback for processing decrypted messages. Default behavior is to print."""
        print(f"\n[{sender}]: {plaintext}")
        # Reprint prompt
        print("> ", end="", flush=True)

    def verify_identity_trust(
        self,
        target_user: str,
        bundle: dict[str, bytes],
    ) -> bool:
        """
        Verify that the bundle's keys match the trusted identity stored locally.
        This simulates checking against a local address book or PKI.
        """
        trusted_file = os.path.join(IDENTITY_DIR, f"{target_user.lower()}.json")
        if not os.path.exists(trusted_file):
            print(
                f"[!] Security Warning: No trusted identity found for {target_user}. Aborting connection."
            )
            return False

        try:
            with open(trusted_file, "r") as f:
                trusted_data = json.load(f)

            # Reconstruct the trusted responder state to get public keys
            trusted_responder = X3DHResponder.from_dict(trusted_data)

            trusted_sik = trusted_responder.SIK_b.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            trusted_ik = trusted_responder.IK_b.public_bytes()

            if bundle["SIK_b"] != trusted_sik:
                print(f"[!] SECURITY ALERT: SIK mismatch for {target_user}!")
                return False

            if bundle["IK_b"] != trusted_ik:
                print(f"[!] SECURITY ALERT: IK mismatch for {target_user}!")
                return False

            return True

        except Exception as e:
            print(f"[!] Failed to verify trusted identity for {target_user}: {e}")
            return False

    def establish_session(self, target: str) -> bool:
        """Perform X3DH to establish session with target"""
        print(f"[*] Establishing session with {target}...")

        bundle_enc = self.get_bundle(target)
        if not bundle_enc:
            print(f"[!] Could not get bundle for {target}. Removing from peers.")
            if target in self.peers:
                self.peers.remove(target)
            return False

        try:
            bundle = {k: b64dec(v) for k, v in bundle_enc.items()}

            # 1. Verify Signatures (Internal Consistency)
            try:
                sik_public = ed25519.Ed25519PublicKey.from_public_bytes(bundle["SIK_b"])
                sik_public.verify(bundle["Sig_IK"], bundle["IK_b"])
                sik_public.verify(bundle["Sig_SPK"], bundle["SPK_b"])
            except Exception as e:
                print(f"[!] Signature verification failed for {target}: {e}")
                return False

            # 2. Verify Trust (Authenticity)
            if not self.verify_identity_trust(target, bundle):
                print(f"[!] Identity verification failed for {target}. Aborting.")
                return False

            if self.x3dh_responder is None:
                print(f"[!] No identity for {self.username}. Cannot establish session.")
                return False

            alice = X3DHInitiator(
                IK=self.x3dh_responder.IK_b,
                EK=generate_key_pair(),
            )
            sk = alice.compute_shared_secret(
                bundle["IK_b"],
                bundle["SPK_b"],
                bundle.get("OPK_b"),
            )

            bob_spk_public = bundle["SPK_b"]
            state = RatchetInitInitiator(
                sk,
                bob_spk_public,
                kdf_rk=KDF_RK,
                kdf_ck=KDF_CK,
                nonce_gen=nonce_gen,
            )
            self.sessions[target] = state

            # Store keys for the first message (INITIAL)
            self.sessions[target].pending_x3dh = {
                "ik_a": alice.IK_a.public_bytes(),
                "ek_a": alice.EK_a.public_bytes(),
            }
            return True
        except Exception as e:
            print(f"[!] X3DH failed with {target}: {e}")
            return False

    def verify_initiator_identity(self, sender: str, ik_a_bytes: bytes) -> bool:
        """
        Verify that the initiator's Identity Key matches the trusted identity.
        """
        trusted_file = os.path.join(IDENTITY_DIR, f"{sender.lower()}.json")
        if not os.path.exists(trusted_file):
            print(
                f"[!] Security Warning: Received session request from unknown user {sender}. Rejecting."
            )
            return False

        try:
            with open(trusted_file, "r") as f:
                trusted_data = json.load(f)

            # Reconstruct to extract public IK
            trusted_responder = X3DHResponder.from_dict(trusted_data)
            trusted_ik = trusted_responder.IK_b.public_bytes()

            if ik_a_bytes != trusted_ik:
                print(
                    f"[!] SECURITY ALERT: Identity Key mismatch for initiator {sender}!"
                )
                return False

            return True
        except Exception as e:
            print(f"[!] Failed to verify initiator identity for {sender}: {e}")
            return False

    def broadcast_message(self, text: str) -> None:
        """Send message to ALL peers"""
        if not self.peers:
            print("[!] No one else is online.")
            return

        # Copy set to avoid modification during iteration
        targets = list(self.peers)

        for target in targets:
            if target == self.username:
                continue

            # 1. Ensure Session Exists
            if target not in self.sessions:
                success = self.establish_session(target)
                if not success:
                    continue

            # 2. Encrypt
            state = self.sessions[target]
            header, nonce, ciphertext, tag = RatchetEncrypt(state, text)

            payload = Payload(
                {
                    "type": "RATCHET",
                    "header": {"dh": b64enc(header.dh), "pn": header.pn, "n": header.n},
                    "ciphertext": b64enc(ciphertext),
                    "nonce": b64enc(nonce),
                    "tag": b64enc(tag),
                    "recipient": target,
                }
            )

            # Check if we need to attach X3DH info (Initial message)
            if state.pending_x3dh is not None:
                payload["type"] = "INITIAL"
                payload["ik_a"] = b64enc(state.pending_x3dh["ik_a"])
                payload["ek_a"] = b64enc(state.pending_x3dh["ek_a"])
                state.pending_x3dh = None

            # 3. Send
            send_msg(
                self.sock,
                {"type": "SEND", "recipient": target, "payload": payload},
            )

    def start_cli(self):
        print("------------------------------------------")
        print(" Global Secure Chat Room")
        print(" commands: /list, /quit")
        print(" Just type a message to broadcast to everyone.")
        print("------------------------------------------")

        while self.running:
            try:
                cmd = input("> ")
                if not cmd:
                    continue

                if cmd.startswith("/quit"):
                    self.disconnect()
                    break
                elif cmd.startswith("/list"):
                    print(f"Online Peers: {list(self.peers)}")
                else:
                    self.broadcast_message(cmd)
            except KeyboardInterrupt:
                break
            except Exception as e:
                import traceback

                traceback.print_exc()
                print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    client = ChatClient(username)
    client.connect()
    client.start_cli()
