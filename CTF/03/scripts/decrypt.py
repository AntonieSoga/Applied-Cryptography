import itertools  # Used for creating pairs of ciphertexts (combinations) for the crib drag.
import string     # Standard string library (though mostly unused here, helpful for constants).

# Read the file 'cyphertexts.txt', strip whitespace, and convert hex strings into byte objects.
# This creates a list of byte-arrays, where each item is one encrypted message.
cts = [bytes.fromhex(s.strip()) for s in open("ctf/03/files/cyphertexts.txt") if s.strip()]


def is_letter(b):
    # Check if a byte 'b' corresponds to an ASCII letter (A-Z or a-z).
    # 65-90 is uppercase, 97-122 is lowercase.
    return 65 <= b <= 90 or 97 <= b <= 122


def is_printable(b):
    # Check if a byte is a standard ASCII printable character (Space through ~).
    # 32 is space, 126 is tilde (~).
    return 32 <= b < 127


def xor_bytes(a, b):
    # A helper function to XOR two byte strings together.
    # It zips them (pairs byte 0 with byte 0, etc.) and performs bitwise XOR (^).
    # Result length is determined by the shorter of the two strings.
    return bytes(x ^ y for x, y in zip(a, b))


def score_plain_byte(b):
    # A heuristic scoring function to judge how likely a decrypted byte is valid English text.
    # This is used by the statistical solver to guess the key.

    # 3.0 points: Space (0x20). In English sentences, space is the most frequent character (~15-20%).
    if b == 32:
        return 3.0
    # 2.0 points: Letters. Common and expected.
    if 65 <= b <= 90 or 97 <= b <= 122:
        return 2.0
    # 0.5 points: Numbers. Less common in prose than letters.
    if 48 <= b <= 57:
        return 0.5
    # 0.5 points: Common punctuation.
    if b in b".,;:'\"!?()-":
        return 0.5
    # 0.0 points: Other printable characters (brackets, math symbols, etc.). Neutral.
    if 32 <= b < 127:
        return 0.0
    # -5.0 points: Non-printable characters (control codes). 
    # These are extremely unlikely in a standard text sentence.
    return -5.0


def statistical_key_fill(cts, key):
    # This function tries to guess unknown key bytes by "brute forcing" individual columns
    # and picking the byte that makes the column look most like English.
    
    maxlen = max(len(c) for c in cts)  # Find the length of the longest message.
    
    # Iterate through every byte position (column) of the key.
    for i in range(maxlen):
        # If we already found this key byte using known plaintext or heuristics, skip it.
        if key[i] is not None:
            continue
        
        best_k = None       # To store the best guess for the key byte.
        best_score = -1e9   # Start with a very low score.
        
        # Try every possible byte value (0-255) as the key for this position.
        for kb in range(256):
            s = 0.0
            # For this guess 'kb', XOR it with the i-th byte of every ciphertext.
            for c in cts:
                if i < len(c):
                    # Add up the 'English score' of the resulting plaintext characters.
                    s += score_plain_byte(c[i] ^ kb)
            
            # If this guess produces the highest score so far, record it.
            if s > best_score:
                best_score = s
                best_k = kb
        
        # Set the key at position i to the winner of the statistical contest.
        key[i] = best_k


def space_heuristic_key(cts, threshold=6):
    # This implements the classic Many-Time Pad attack logic.
    # Logic: Space (0x20) XOR Letter (0x41..0x5A) results in a byte that LOOKS like a letter.
    # If Cipher1[i] ^ Cipher2[i] is a letter, it is highly probable that either P1[i] or P2[i] is a space.
    
    # Initialize a score counter for every byte of every message.
    scores = [[0] * len(c) for c in cts]
    
    # Compare every ciphertext against every other ciphertext.
    for i in range(len(cts)):
        for j in range(i + 1, len(cts)):
            x = xor_bytes(cts[i], cts[j]) # C1 ^ C2
            
            for k, b in enumerate(x):
                # If the XOR result is a letter...
                if is_letter(b):
                    # Increment the 'space likelihood' score for both messages at this index.
                    scores[i][k] += 1
                    scores[j][k] += 1

    maxlen = max(len(c) for c in cts)
    key = [None] * maxlen
    
    # Iterate through scores to deduce the key.
    for i, c in enumerate(cts):
        for k, sc in enumerate(scores[i]):
            # If a specific position in message 'i' caused a letter-XOR result >= 6 times,
            # we are very confident that Plaintext[i][k] is a Space (0x20).
            # Since C = P ^ K, we know K = C ^ P. Therefore K = C ^ 0x20.
            if sc >= threshold and key[k] is None:
                key[k] = c[k] ^ 0x20
    return key


def decrypt_with_key(ct, key):
    # Decrypts a single ciphertext using the current master key.
    out = []
    for i, b in enumerate(ct):
        # If we have a valid key byte for this position:
        if i < len(key) and key[i] is not None:
            # XOR ciphertext byte with key byte
            p = b ^ key[i]
            # Convert to char if printable, otherwise put '?'
            out.append(chr(p) if is_printable(p) else "?")
        else:
            # If we don't know the key byte yet, output '?'
            out.append("?")
    return "".join(out)


def apply_known_plaintext(ct, plaintext, key, label=""):
    # This is used when we know (or guess) a specific phrase in a specific message.
    # It recovers the key for those positions because Key = Cipher ^ Plain.
    pt = plaintext.encode()
    conflicts = 0
    
    for i, ch in enumerate(pt):
        if i < len(ct):
            # Calculate what the key byte MUST be for this plaintext char to exist.
            kb = ct[i] ^ ch
            
            # If we haven't found this key byte yet, save it.
            if key[i] is None:
                key[i] = kb
            # If we already have a key byte there, check if it matches.
            # If it doesn't match, our known plaintext guess is probably wrong (or alignment is off).
            elif key[i] != kb:
                conflicts += 1
                
    # Warn user if the known plaintext conflicts with previously derived key bytes.
    if conflicts and label:
        print(f"[warn] {label}: {conflicts} key conflicts ignored")


def crib_drag(cts, crib, min_printable=0.9):
    # A tool for manual analysis.
    # "Dragging" a crib (guess word) across the XOR of two ciphertexts.
    # If (C1 ^ C2) ^ "THE" results in readable text, then "THE" is likely in one of the messages.
    crib_bytes = crib.encode()
    
    # Try every pair of ciphertexts.
    for a, b in itertools.combinations(range(len(cts)), 2):
        x = xor_bytes(cts[a], cts[b]) # The XOR map of the two messages
        
        # Slide the crib across the XOR map.
        for off in range(0, len(x) - len(crib_bytes) + 1):
            # Attempt to retrieve the text of the *other* message assuming the crib is in message 'a' or 'b'.
            guess = bytes(x[off + i] ^ crib_bytes[i] for i in range(len(crib_bytes)))
            
            # Check what percentage of the result is printable characters.
            printable = sum(is_printable(c) for c in guess) / len(guess)
            
            # If 90% or more characters are printable, print the result for the user to check.
            if printable >= min_printable:
                preview = "".join(chr(c) if is_printable(c) else "." for c in guess)
                print(f"pair {a}-{b} off {off} -> {preview}")


def main():
    # Find the maximum length to initialize the key array.
    maxlen = max(len(c) for c in cts)
    # The master key array. None indicates an unknown byte.
    key = [None] * maxlen
    
    # 1. LOCK IN THE KNOWN SOLUTION
    # We identified that ciphertext #8 contains the instructions.
    # We hardcode this known text to recover a huge chunk of the key immediately.
    known_msg_8 = (
        "To whom it may concern: you want to capture the flag, don't you? "
        "You won't find it in THIS plaintext, for the flag is the NAME of "
        "George's musical composition, which SHALL be written in capital letters."
    )
    # Apply this known text to recover key bytes.
    apply_known_plaintext(cts[8], known_msg_8, key, label="known_msg_8")

    # 2. APPLY KNOWN QUOTES
    # Based on partial decrypts from previous runs, we Googled the texts
    # and found the exact source quotes (Beowulf, Ion Creanga, Tolkien, etc.).
    # We apply these to fill in even more key bytes.
    APPLY_KNOWN_QUOTES = True
    known_quotes = {
        0: "In that time there was not among the Geats a treasure or rich gift more excellent in form of sword.",
        1: "I do not know about others, but when I think of my childhood home from Humulesti",
        2: "Many a dreadful path in sooth there lies before thy feet -- and after Morgoth, still a fleet untiring hate, as I know well,would hunt thee from heaven unto hell. Feanor's sons would, if they could,slay thee or ever thou reached his wood or laid in Thingol's lap that fire,or gained at least thy sweet desire.",
        3: "But the way of the righteous ones is like the shining light",
        4: "It stands to reason, that good is what you ought to prefer",
        6: "Good night, Charles. Shall we ever see a night such as this!",
    }
    if APPLY_KNOWN_QUOTES:
        for idx, quote in known_quotes.items():
            apply_known_plaintext(cts[idx], quote, key, label=f"quote_{idx}")

    # 3. FILL GAPS WITH SPACE HEURISTIC
    # For parts of the key not covered by the quotes above, we use the space heuristic.
    # (Threshold=6 means we need 6 messages to agree a spot is a space before we trust it).
    space_key = space_heuristic_key(cts, threshold=6)
    for i, kb in enumerate(space_key):
        # Only fill if we don't already have a key byte (don't overwrite known text).
        if key[i] is None:
            key[i] = kb

    # 4. FILL REMAINING GAPS STATISTICALLY
    # If there are still 'None' values in the key, guess the byte that produces the best English score.
    statistical_key_fill(cts, key)

    # Print the final decrypted messages.
    for i, c in enumerate(cts):
        print(f"{i}: {decrypt_with_key(c, key)}")

    # Optional: Logic for testing a guess word (Crib Dragging).
    # This was used to find the "known_quotes" originally.
    cribs = [
        "RHAPSODY_IN_BLUE", # Example of a wrong guess for the flag to see if it fits anywhere.
    ]
    for crib in cribs:
        crib_drag(cts, crib)


if __name__ == "__main__":
    main()