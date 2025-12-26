import requests
import base64
import collections

# Challenge configuration
URL = "http://141.85.224.115:7201/"
# 20,000 blocks of 16 bytes each is usually enough for statistical significance
NUM_BLOCKS = 20000 
BLOCK_SIZE = 16

def solve():
    print(f"[*] Generating {NUM_BLOCKS} blocks of null bytes...")
    # Create a plaintext consisting of only null bytes
    plaintext = b"\x00" * (NUM_BLOCKS * BLOCK_SIZE)
    encoded_pt = base64.b64encode(plaintext).decode()

    print("[*] Sending request to server (this may take a moment)...")
    try:
        response = requests.post(URL, json={"plaintext": encoded_pt})
        response.raise_for_status()
    except Exception as e:
        print(f"[!] Error connecting to server: {e}")
        return

    print("[*] Decoding ciphertext...")
    ciphertext = base64.b64decode(response.text)
    
    # Split the ciphertext into 16-byte blocks
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    
    print("[*] Performing frequency analysis at each byte position...")
    recovered_key = bytearray(BLOCK_SIZE)

    for i in range(BLOCK_SIZE):
        # Extract the i-th byte from every block
        column = [block[i] for block in blocks if len(block) == BLOCK_SIZE]
        
        # Find the most frequent byte value at this position
        # Because P is null, C = Pad. The key byte leaks into the Pad.
        counter = collections.Counter(column)
        most_common_byte, count = counter.most_common(1)[0]
        
        recovered_key[i] = most_common_byte
        print(f"  Pos {i:02d}: Found 0x{most_common_byte:02x} (Occurrences: {count})")

    # Format the final flag
    # The key is likely an ASCII string or a hex-encoded string
    try:
        key_str = recovered_key.decode('ascii')
        print(f"\n[+] Recovered Key (ASCII): {key_str}")
        print(f"[+] Flag: CRYPTO_CTF{{{key_str}}}")
    except UnicodeDecodeError:
        key_hex = recovered_key.hex()
        print(f"\n[+] Recovered Key (Hex): {key_hex}")
        print(f"[+] Flag: CRYPTO_CTF{{{key_hex}}}")

if __name__ == "__main__":
    solve()