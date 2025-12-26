"""
Private chat

Encrypt messages given a secret. Usage example:

python encrypt.py \
    -m "hi!" \
    -s secret.bin \
    -o message.enc

Make sure to install cryptography before:

pip install cryptography
"""

import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def pkcs7_padding(message: bytes, block_size: int) -> bytes:
    padding_length = block_size - (len(message) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding


def encrypt(message: bytes, secret: int) -> bytes:
    key = secret.to_bytes(16, "big")
    padded_data = pkcs7_padding(message, block_size=16)
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.ECB(),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def main() -> None:
    parser = argparse.ArgumentParser(description="Private Chat")
    parser.add_argument("-m", "--message", help="The message to encrypt")
    parser.add_argument("-s", "--secret_path", help="Path to the secret file")
    parser.add_argument("-o", "--output_path", help="Path to encrypted output")
    args = parser.parse_args()

    with open(args.secret_path, "rb") as f:
        secret = int.from_bytes(f.read(), "big")
    with open(args.output_path, "wb") as f:
        f.write(encrypt(args.message.encode(), secret))


if __name__ == "__main__":
    main()
