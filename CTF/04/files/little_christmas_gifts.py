import os
import math
import base64
import random
from Crypto.Util.number import getPrime

header = f"""=== Trei pastori ===

Trei pastori se intalnira
Trei pastori se intalnira
[REDACTED]
"""

assert(header.startswith("=== Trei pastori ===\n\nTrei pastori se intalnira\nTrei pastori se intalnira\n"))

flag = '[REDACTED]'

footer = '[REDACTED]'

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

class LCG:
    def __init__(self):
        self.mod = getPrime(64)
        self.a = int.from_bytes(os.urandom(8), "little") % self.mod
        self.b = int.from_bytes(os.urandom(8), "little") % self.mod
        self.state = int.from_bytes(os.urandom(8), "little") % self.mod

    def next(self):
        self.state = (self.a * self.state + self.b) % self.mod
        return self.state

if __name__ == '__main__':
    plaintext = (header + flag + footer).encode()
    lcg = LCG()
    states = [lcg.next() for _ in range(math.ceil(len(plaintext) / 8))]

    key = b"".join([state.to_bytes(8, "little") for state in states])
    ciphertext = xor(plaintext, key)

    with open('gifts.enc', 'wb') as f:
        f.write(ciphertext)


