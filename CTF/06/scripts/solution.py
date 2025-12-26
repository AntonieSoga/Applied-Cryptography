import requests
import json

# Configuration
TARGET_URL = "http://141.85.224.115:7204/oracle"
HEX_CT = "436f6e67726174756c6174696f6e73219e6e9643756024011984791253b45fdb0e9cf64ea46bb8ef4b5cd8a4104a4314929d8f15a941c32a689cd6fa0a4133b7"

def is_padding_valid(hex_payload):
    """Sends ciphertext to server and returns True if padding is valid."""
    try:
        response = requests.post(TARGET_URL, json={"ciphertext": hex_payload}, timeout=5)
        # Usually, the server returns 500 or a specific message for 'Invalid Padding'
        # We assume 'Invalid padding' is the failure message.
        return "padding" not in response.text.lower() and response.status_code != 500
    except Exception as e:
        return False

def run_attack():
    ct_bytes = bytes.fromhex(HEX_CT)
    # Split into 16-byte blocks
    blocks = [ct_bytes[i:i+16] for i in range(0, len(ct_bytes), 16)]
    num_blocks = len(blocks)
    
    full_plaintext = ""

    # Start from the last block and work backwards
    for block_num in range(num_blocks - 1, 0, -1):
        print(f"\n[!] Cracking Block {block_num}...")
        
        prev_block = list(blocks[block_num - 1])
        current_block = blocks[block_num]
        
        intermediate = [0] * 16
        plaintext_block = [0] * 16
        
        # Crack bytes from right (15) to left (0)
        for byte_pos in range(15, -1, -1):
            expected_pad = 16 - byte_pos
            
            # Try all 256 possibilities for the byte
            for candidate in range(256):
                # Prepare a modified version of the PREVIOUS block
                test_prev = [0] * 16
                
                # Set bytes to the right to satisfy the current padding requirements
                for j in range(byte_pos + 1, 16):
                    test_prev[j] = intermediate[j] ^ expected_pad
                
                test_prev[byte_pos] = candidate
                
                # Send (Modified Prev Block + Current Block)
                payload = bytes(test_prev).hex() + current_block.hex()
                
                if is_padding_valid(payload):
                    # We found the correct candidate!
                    # Intermediate = Candidate XOR ExpectedPad
                    inter_val = candidate ^ expected_pad
                    intermediate[byte_pos] = inter_val
                    
                    # Plaintext = Intermediate XOR Original Prev Block Byte
                    p_byte = inter_val ^ prev_block[byte_pos]
                    plaintext_block[byte_pos] = p_byte
                    
                    char_repr = chr(p_byte) if 32 <= p_byte <= 126 else f"\\x{p_byte:02x}"
                    print(f"    Byte {byte_pos:02d} found: {char_repr}")
                    break
            else:
                print(f"    [X] Failed to crack byte {byte_pos}. Check oracle logic.")

        block_str = "".join(chr(b) for b in plaintext_block if 32 <= b <= 126)
        full_plaintext = block_str + full_plaintext
        print(f"[+] Decrypted Block {block_num}: {block_str}")

    print(f"\n[***] FULL DECRYPTED MESSAGE: {full_plaintext}")

if __name__ == "__main__":
    run_attack()