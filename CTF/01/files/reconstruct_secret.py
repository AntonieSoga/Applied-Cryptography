# reconstruct_and_decrypt.py
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

p = 170141183460469231731687303715884105727
shares = [
    (1, 41588560628171152593688072686229718387),
    (2, 102367892015091791145384104860017242567),
    (3, 137046074329932719059328595132049831898),
]

def reconstruct_secret(shares, p):
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % p
            den = (den * (xi - xj)) % p
        inv_den = pow(den, -1, p)
        secret = (secret + yi * num * inv_den) % p
    return secret

def pkcs7_unpad(data):
    pad = data[-1]
    return data[:-pad]

secret = reconstruct_secret(shares, p)
key = secret.to_bytes(16, "big")

with open("flag.enc", "rb") as f:
    ciphertext = f.read()

cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()
plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

print(pkcs7_unpad(plaintext_padded).decode())
