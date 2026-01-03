#!/usr/bin/env python3
# -*- coding: ascii -*-

# Import ast to safely parse Python dict literals from the log lines.
import ast
# Import base64 for decoding the intercepted JSON fields.
import base64
# Import sys for command-line argument handling.
import sys
# Import AESGCM for authenticated decryption checks during brute force.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Define a helper to base64-decode strings from the JSON payload.
def b64dec(s: str) -> bytes:
    # Convert a base64-encoded string into raw bytes.
    return base64.b64decode(s)

# Re-implement the challenge's expand_seed to derive a 32-byte chain key.
def expand_seed(seed_bytes: bytes) -> bytes:
    # Interpret the 3-byte seed as a big-endian integer.
    seed_int = int.from_bytes(seed_bytes, "big")
    # Accumulate output until we have 32 bytes.
    output = b""
    # Start a small counter to generate successive 3-byte blocks.
    counter = 0
    # Keep appending 3-byte blocks until output reaches 32 bytes.
    while len(output) < 32:
        # Derive a 24-bit value by adding the counter modulo 2^24.
        val = (seed_int + counter) % (2**24)
        # Append the 24-bit value as 3 big-endian bytes.
        output += val.to_bytes(3, "big")
        # Advance the counter for the next block.
        counter += 1
    # Truncate to exactly 32 bytes as the chain key.
    return output[:32]

# Build the associated data exactly like the client: ad || dh || pn || n.
def concat_ad_header(dh: bytes, pn: int, n: int) -> bytes:
    # Encode pn and n as 4-byte big-endian integers and concatenate.
    return dh + pn.to_bytes(4, "big") + n.to_bytes(4, "big")

# Attempt to brute-force a single intercepted payload.
def bruteforce_payload(payload: dict[str, object]) -> str | None:
    # Decode header fields.
    header = payload["header"]
    # Extract and decode the ratchet public key from base64.
    dh = b64dec(header["dh"])
    # Read the previous chain length.
    pn = int(header["pn"])
    # Read the message number within the chain.
    n = int(header["n"])
    # Decode the nonce from base64.
    nonce = b64dec(payload["nonce"])
    # Decode the ciphertext from base64.
    ciphertext = b64dec(payload["ciphertext"])
    # Decode the GCM tag from base64.
    tag = b64dec(payload["tag"])
    # Construct associated data to authenticate the header.
    ad = concat_ad_header(dh, pn, n)

    # The chain KDF increments by 1 before yielding the message key.
    offset = n + 1

    # Brute-force all 2^24 possible 3-byte seeds.
    for seed in range(2**24):
        # Convert the seed integer into exactly 3 bytes.
        seed_bytes = seed.to_bytes(3, "big")
        # Expand the 3-byte seed into the 32-byte chain key.
        ck0 = expand_seed(seed_bytes)
        # Derive the message key by adding the offset modulo 2^256.
        mk_int = (int.from_bytes(ck0, "big") + offset) % (2**256)
        # Convert the message key back to 32 bytes.
        mk = mk_int.to_bytes(32, "big")
        # Try AES-GCM decryption; InvalidTag means wrong key.
        try:
            # Decrypt ciphertext+tag with the candidate message key.
            plaintext = AESGCM(mk).decrypt(nonce, ciphertext + tag, ad)
            # Return the plaintext as UTF-8 if decryption succeeds.
            return plaintext.decode("utf-8")
        # Catch any exception as a failed candidate key.
        except Exception:
            # Ignore and continue brute-forcing.
            pass

    # Return None if no key succeeded.
    return None

# Extract the Python dict payload from a single intercepted log line.
def parse_payload_line(line: str) -> dict[str, object] | None:
    # Find the first brace which starts the dict literal.
    brace_index = line.find("{")
    # Return None if no dict literal is present.
    if brace_index == -1:
        return None
    # Slice out the dict literal substring.
    dict_text = line[brace_index:]
    # Parse the dict literal into a Python object.
    payload = ast.literal_eval(dict_text)
    # Only accept dict payloads.
    if not isinstance(payload, dict):
        return None
    # Return the parsed payload.
    return payload

# Run brute-force on each intercepted line from a file.
def main() -> None:
    # Require a file path argument.
    if len(sys.argv) != 2:
        # Print usage if the user did not provide a file path.
        print("Usage: python3 bruteforce_gcm.py <intercepts.txt>")
        # Exit with a non-zero status for incorrect usage.
        sys.exit(1)

    # Read the input file path from argv.
    input_path = sys.argv[1]

    # Open the file and iterate over each line.
    with open(input_path, "r", encoding="utf-8") as f:
        # Track a line counter for reporting.
        line_num = 0
        # Process each line in the file.
        for raw_line in f:
            # Increment the line counter.
            line_num += 1
            # Strip whitespace to handle blank lines.
            line = raw_line.strip()
            # Skip empty lines.
            if not line:
                continue
            # Parse the payload dict from the intercepted log line.
            payload = parse_payload_line(line)
            # Report parse failures and continue.
            if payload is None:
                print(f"[line {line_num}] [!] Failed to parse payload.")
                continue
            # Attempt to brute-force the payload.
            result = bruteforce_payload(payload)
            # Print plaintext as soon as it is recovered.
            if result is not None:
                print(f"[line {line_num}] {result}")
            # Print a failure message if no key was found.
            else:
                print(f"[line {line_num}] [!] No key found.")

# Execute the demo when run as a script.
if __name__ == "__main__":
    # Call main to start the brute-force demo.
    main()
