from Crypto.Util.number import inverse, long_to_bytes
import math

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# 1. Setup known data
known_header = b"=== Trei pastori ===\n\nTrei pastori se intalnira\nTrei pastori se intalnira\n"

with open(r'CTF\04\files\gifts.enc', 'rb') as f:
    ciphertext = f.read()

# 2. Recover the first few states of the LCG
# Each state is 8 bytes, little-endian
keystream_segment = xor(ciphertext[:72], known_header[:72])
states = [int.from_bytes(keystream_segment[i:i+8], "little") for i in range(0, 72, 8)]

# 3. Recover the modulus (m)
diffs = [states[i+1] - states[i] for i in range(len(states)-1)]
# For an LCG, (d[i+1]*d[i-1] - d[i]^2) is always a multiple of m
multiples_of_m = []
for i in range(1, len(diffs)-1):
    multiples_of_m.append(abs(diffs[i+1] * diffs[i-1] - diffs[i]**2))

m = multiples_of_m[0]
for val in multiples_of_m[1:]:
    m = math.gcd(m, val)

# Since m is a 64-bit prime, if the GCD is larger than 64-bits, 
# we divide out small factors or just use it if it's prime.
# In most CTF cases, the GCD will be exactly m.

# 4. Recover a and b
a = ((states[2] - states[1]) * inverse(states[1] - states[0], m)) % m
b = (states[1] - a * states[0]) % m

# 5. Reconstruct the full keystream
current_state = states[0]
full_keystream = b""
for _ in range(math.ceil(len(ciphertext) / 8)):
    # Calculate next state
    current_state = (a * current_state + b) % m
    full_keystream += current_state.to_bytes(8, "little")

# Note: The script's `lcg.next()` is called BEFORE the first block.
# So states[0] we recovered is actually the result of the first next() call.
# We must regenerate starting from the first known state.
current_state = states[0]
recovered_states = [current_state]
for _ in range(len(states), math.ceil(len(ciphertext) / 8) + 1):
    current_state = (a * current_state + b) % m
    recovered_states.append(current_state)

# Combine states into key (skipping the already known states if you prefer, 
# but generating from scratch is cleaner)
full_key = b"".join([s.to_bytes(8, "little") for s in states])
# Continue from the last known state
temp_state = states[-1]
for _ in range(len(states), math.ceil(len(ciphertext) / 8)):
    temp_state = (a * temp_state + b) % m
    full_key += temp_state.to_bytes(8, "little")

# 6. Decrypt
decrypted = xor(ciphertext, full_key)
print(decrypted.decode(errors='ignore'))