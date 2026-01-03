import os
import string

def get_char_score(c):
    """Refined scoring to filter out 'lucky guesses' that produce garbage."""
    if chr(c) in string.ascii_lowercase or c == ord(' '):
        return 2.5
    if chr(c) in string.ascii_uppercase:
        return 2.0
    if chr(c) in "0123456789.,!?;:'\"-()":
        return 1.0
    if 32 <= c <= 126:
        return 0.1
    return -15.0

def solve():
    # Setup path
    path = r"ctf\03\files\cyphertexts.txt"
    if not os.path.exists(path):
        print("File not found.")
        return

    with open(path, 'r') as f:
        cts = [bytes.fromhex(line.strip()) for line in f if line.strip()]

    max_len = max(len(c) for c in cts)
    key = [None] * max_len

    # ANSI Escape codes for terminal highlighting
    # Green and Bold for Uppercase, Reset for others
    HIGHLIGHT = '\033[1;32m'
    ENDC = '\033[0m'

    # Vertical statistical attack
    for col in range(max_len):
        best_byte = None
        max_score = -float('inf')

        for candidate_key in range(256):
            current_score = 0
            all_printable = True
            
            for ct in cts:
                if col < len(ct):
                    p_char = ct[col] ^ candidate_key
                    current_score += get_char_score(p_char)
                    if p_char < 32 or p_char > 126:
                        all_printable = False
            
            if all_printable:
                current_score += 25  # Strong bonus for a 'perfect' column
            
            if current_score > max_score:
                max_score = current_score
                best_byte = candidate_key

        # Accuracy Threshold: If the score is too low, we mark it as unknown (*)
        # We only accept the key if it significantly improves the readability
        if max_score > 15: 
            key[col] = best_byte

    # Display results
    print(f"{'Line':<2} | Deciphered Text (* = placeholder, Green = Uppercase)")
    print("-" * 110)
    for i, ct in enumerate(cts):
        output = ""
        for pos in range(len(ct)):
            if key[pos] is not None:
                char_code = ct[pos] ^ key[pos]
                char = chr(char_code)
                
                if 'A' <= char <= 'Z':
                    output += f"{HIGHLIGHT}{char}{ENDC}"
                else:
                    output += char
            else:
                output += "*"
        print(f"{i:<2} | {output}")

if __name__ == "__main__":
    solve()