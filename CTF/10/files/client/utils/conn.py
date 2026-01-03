import base64
import json
import socket
import struct
from typing import Literal, NotRequired, TypedDict, cast


class PayloadHeader(TypedDict):
    dh: str
    pn: int
    n: int


class Payload(TypedDict):
    type: Literal["INITIAL", "RATCHET"]
    header: PayloadHeader
    ciphertext: str
    nonce: str
    tag: str
    ik_a: NotRequired[str]  # Only for INITIAL messages
    ek_a: NotRequired[str]  # Only for INITIAL messages
    recipient: str | None


class RegisterMessage(TypedDict):
    type: Literal["REGISTER"]
    username: str
    bundle: dict[str, str]
    server_sig: NotRequired[str]


class FetchBundleMessage(TypedDict):
    type: Literal["FETCH_BUNDLE"]
    username: str
    server_sig: NotRequired[str]


class SendMessage(TypedDict):
    type: Literal["SEND"]
    recipient: str
    payload: Payload
    server_sig: NotRequired[str]


class MessageReceived(TypedDict):
    type: Literal["MESSAGE"]
    sender: str
    payload: Payload | None
    server_sig: NotRequired[str]


class ErrorMessage(TypedDict):
    type: Literal["ERROR"]
    message: str
    server_sig: NotRequired[str]


class UserJoinedMessage(TypedDict):
    type: Literal["USER_JOINED"]
    username: str
    server_sig: NotRequired[str]


class UserLeftMessage(TypedDict):
    type: Literal["USER_LEFT"]
    username: str
    server_sig: NotRequired[str]


class RegisterSuccessMessage(TypedDict):
    type: Literal["REGISTER_SUCCESS"]
    users: list[str]
    server_sig: NotRequired[str]


class BundleMessage(TypedDict):
    type: Literal["BUNDLE"]
    username: str
    bundle: dict[str, str]
    server_sig: NotRequired[str]


Message = (
    RegisterMessage
    | FetchBundleMessage
    | SendMessage
    | MessageReceived
    | ErrorMessage
    | UserJoinedMessage
    | UserLeftMessage
    | RegisterSuccessMessage
    | BundleMessage
)


def send_msg(sock: socket.socket, msg: Message) -> None:
    """Send a JSON message with a 4-byte big-endian length prefix."""
    msg_bytes = json.dumps(msg).encode("utf-8")
    header = struct.pack(">I", len(msg_bytes))
    sock.sendall(header + msg_bytes)


def recv_msg(sock: socket.socket) -> Message | None:
    """Receive a length-prefixed JSON message."""
    # Read 4-byte length header
    raw_len = recv_all(sock, 4)
    if not raw_len:
        return None
    msg_len = cast(int, struct.unpack(">I", raw_len)[0])

    # Read the message body
    data = recv_all(sock, msg_len)
    if not data:
        return None

    return cast(Message, json.loads(data.decode("utf-8")))


def recv_all(sock: socket.socket, n: int) -> bytes | None:
    """Helper to ensure we read exactly n bytes."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64dec(s: str) -> bytes:
    return base64.b64decode(s)
