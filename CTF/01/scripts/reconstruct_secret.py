# reconstruct_and_decrypt.py

# Import the necessary backend to handle cryptographic operations (OpenSSL bindings usually).
from cryptography.hazmat.backends import default_backend
# Import the Cipher class, the AES algorithm, and the ECB mode of operation.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# This is the large Prime number used as the modulus.
# Shamir's Secret Sharing works over a Finite Field defined by this prime (GF(p)).
# All math operations (add, sub, mult, div) must be done modulo p.
p = 170141183460469231731687303715884105727

# These are the specific "shares" or points (x, y) given in the challenge.
# In Shamir's scheme, the secret is the point where x = 0 (the y-intercept).
# We need at least k shares to reconstruct a polynomial of degree k-1.
shares = [
    (1, 41588560628171152593688072686229718387),
    (2, 102367892015091791145384104860017242567),
    (3, 137046074329932719059328595132049831898),
]

# This function implements Lagrange Interpolation to find f(0).
# f(0) is the constant term of the polynomial, which represents our secret.
def reconstruct_secret(shares, p):
    secret = 0  # Initialize the secret accumulator to 0.

    # Loop through each share (x_i, y_i) to calculate its Lagrange basis polynomial L_i.
    # The formula is: L(0) = Sum( y_i * Product( -x_j / (x_i - x_j) ) )
    for i, (xi, yi) in enumerate(shares):
        num = 1  # Numerator accumulator
        den = 1  # Denominator accumulator

        # Inner loop: Calculate the product term for the current share i.
        # We iterate over all other shares j where j != i.
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue  # Skip the current share itself (standard Lagrange formula).

            # Multiply numerator by -x_j (because we are evaluating at x=0).
            # We apply % p at every step to keep numbers within the finite field.
            num = (num * (-xj)) % p

            # Multiply denominator by (x_i - x_j).
            den = (den * (xi - xj)) % p

        # Calculate the Modular Multiplicative Inverse of the denominator.
        # In modular arithmetic, there is no division. Instead, we multiply by the inverse.
        # pow(a, -1, p) efficiently computes (1/a) mod p using Fermat's Little Theorem or extended Euclidean alg.
        inv_den = pow(den, -1, p)

        # Add the contribution of this share to the total secret.
        # Term = y_i * numerator * (1/denominator)
        secret = (secret + yi * num * inv_den) % p

    return secret  # This integer is the recovered AES key.

# Helper function to remove PKCS#7 padding.
# Block ciphers (like AES) require input to be a multiple of the block size (16 bytes).
# Padding adds bytes to fill the space. We must remove them to read the flag.
def pkcs7_unpad(data):
    # In PKCS#7, the value of the last byte tells you exactly how many padding bytes were added.
    # E.g., if the last byte is \x04, it means there are 4 bytes of padding.
    pad = data[-1]

    # Slice the data to remove the last 'pad' number of bytes.
    return data[:-pad]

# Call the function to recover the large integer secret using the provided shares and prime.
secret = reconstruct_secret(shares, p)

# Convert the recovered integer secret into a raw byte string.
# 16 bytes = 128 bits, which implies this is an AES-128 key.
# 'big' (Big Endian) is the standard byte order for cryptographic numbers.
key = secret.to_bytes(16, "big")

# Open the encrypted flag file in 'read binary' (rb) mode.
with open("ctf/01/files/flag.enc", "rb") as f:
    ciphertext = f.read()

# Initialize the AES Cipher object.
# Algorithm: AES using the recovered 'key'.
# Mode: ECB (Electronic Codebook). Note: ECB is insecure because identical blocks encipher to identical ciphertext,
# but it is very common in simple CTF challenges.
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

# Create a decryptor object from the cipher configuration.
decryptor = cipher.decryptor()

# Perform the decryption.
# update(ciphertext) processes the data, and finalize() handles any remaining buffering (though ECB usually doesn't buffer).
plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Remove the padding from the decrypted text, decode bytes to string, and print the flag.
print(pkcs7_unpad(plaintext_padded).decode())