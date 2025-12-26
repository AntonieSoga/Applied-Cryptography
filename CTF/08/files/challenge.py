#!/usr/bin/env python3

import sys

from binascii import hexlify, unhexlify

import random
import sys
from phe import paillier

FLAG = b"you wanted the flag? lol try harder"
FLAG = int.from_bytes(FLAG, "big")

#print("Generating keys...")
public_key, private_key = paillier.generate_paillier_keypair()


def read_line(fd):
    data = b''

    while not data.endswith(b'\n'):
        byte = fd.read(1)
        if byte == b'':
            return data
        data += byte

    return data[:-1].decode().strip()


def write_line(fd, msg):
    fd.write(msg + b'\n')
    fd.flush()


def encrypt(reader, writer):
    write_line(writer, b"Enter data to encrypt (integer): ")
    data = read_line(reader)

    try:
        data = int(data)
        encrypted_data = public_key.encrypt(data)
        write_line(writer, f"Encrypted data: {encrypted_data.ciphertext()}\n".encode())

    except ValueError:
        write_line(writer, b"Invalid input. Please provide a valid integer.\n")

def decrypt(reader, writer):
    write_line(writer, b"Enter data to decrypt (integer ciphertext): ")
    data = read_line(reader)

    try:
        encrypted_data = int(data)
        decrypted_data = private_key.decrypt(paillier.EncryptedNumber(public_key, encrypted_data))

        if decrypted_data == FLAG:
            write_line(writer, b"im here to annoy you before I send you the flag\n")
            write_line(writer, b"use pwntools recvuntil() and problem's solved\n")

        write_line(writer, f"Decrypted data: {decrypted_data}\n".encode())

    except ValueError:
        write_line(writer, b"Invalid input. Please provide a valid ciphertext.\n")

    except Exception as e:
        write_line(writer, f"Error during decryption: {str(e)}\n".encode())

def return_flag(writer):
    encrypted_flag = public_key.encrypt(FLAG)
    value = random.randint(0, 2**4096)
    ct = (encrypted_flag.ciphertext() + value) * 1337

    write_line(writer, f"Ciphertext: {ct}\n".encode())
    write_line(writer, f"Value: {value}\n".encode())


def run_challenge(reader, writer):
    while True:
        try:
            write_line(writer, b"1. Encrypt\n" +
                               b"2. Decrypt\n" +
                               b"3. Return flag\n" +
                               b"4. Exit\n" +
                               b"Choose an option: ")
            option = read_line(reader)

            if not option:
                break  # Disconnect if client sends empty data
            if option == "1":
                encrypt(reader, writer)
            elif option == "2":
                decrypt(reader, writer)
            elif option == "3":
                return_flag(writer)
            elif option == "4":
                write_line(writer, b"Goodbye!")
                break
            else:
                write_line(writer, b"Invalid option. Try again.")

        except Exception:
            print(Exception)
            write_line(writer, b"Error!")


def main():
    # Run the challenge
    return run_challenge(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    sys.exit(main())
