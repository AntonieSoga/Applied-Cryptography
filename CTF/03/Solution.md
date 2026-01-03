# Perfect Secrecy Ex3 - Writeup

## Overview
The challenge involved a set of 9 plaintexts encrypted with the same One-Time Pad (OTP) key. Reusing a key in this manner degrades the scheme into a **Many-Time Pad**, introducing a critical vulnerability: XORing two ciphertexts eliminates the key ($C_1 \oplus C_2 = P_1 \oplus P_2$), allowing for statistical recovery of the plaintexts.

## Methodology

### 1. Key Recovery Strategy
We utilized a Python script to perform the following attacks:
*   **Space Heuristic:** We analyzed columns where $C_x \oplus C_y$ resulted in an alphabetic character. In English, the space character (0x20) is the most common; if $P_x$ is a space, then $P_x \oplus P_y$ reveals the letter case of $P_y$.
*   **Statistical Analysis:** We scored potential key bytes based on how "English-like" the resulting plaintexts looked (frequency analysis of letters vs. non-printable characters).
*   **Known Plaintext Attack:** Once fragments of text became readable, we identified specific quotes (e.g., *Beowulf*, *The Silmarillion*, *Proverbs*). We used the exact text of these quotes to recover the key fully for those segments.

### 2. The Instruction
Decrypting the final message (Quote 8) revealed the objective:

> "To whom it may concern: you want to capture the flag, don't you? You won't find it in THIS plaintext, for the flag is the **NAME** of George's musical composition, which **SHALL** be written in capital letters."

### 3. Solving the Riddle
The flag wasn't in the text itself but hidden in the **capitalization anomalies** of the other decrypted quotes. By aggregating the oddly capitalized words across the messages, we reconstructed a hidden sentence:

*   **Quote 0:** `UNTO`, `US`
*   **Quote 1:** `CHILD`, `IS`, `BORN`
*   **Quote 4:** `SON`, `GIVEN`
*   **Quote 5:** `AND`, `GOVERNMENT`
*   **Quote 6:** `SHALL`, `BE`, `UPON`
*   **Quote 7:** `HIS`, `SHOULDERS`
*   **Quote 8:** `NAME`

**Reconstructed Verse:**
> *"For **UNTO US** a **CHILD IS BORN**, unto us a **SON** is **GIVEN**; **AND** the **GOVERNMENT SHALL BE UPON HIS SHOULDERS**; and his **NAME**..."*

### 4. The Connection
This text is from **Isaiah 9:6**. It is most famously known as the chorus lyrics from the oratorio **Messiah**, composed by **George Frideric Handel**.

*   **George:** George Frideric Handel
*   **Musical Composition:** Messiah

## Flag
According to the instructions, the flag is the name of the composition in capital letters.

`CRYPTO_CTF{MESSIAH}`