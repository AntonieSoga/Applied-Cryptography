# do_you_have_signal_ex10 - Writeup

## Summary
This challenge implements a Signal-like X3DH + Double Ratchet chat, but the client
contains critical cryptographic misconfigurations that make passive decryption
feasible. By intercepting broadcast traffic, I can brute-force the message keys
and recover plaintexts (including the flag).

## Key Misconfigurations
1) **Low-entropy chain keys**
- In `client/client.py`, `KDF_RK` truncates to 3 bytes and expands via `expand_seed`.
- That creates a 24-bit chain key space (`2^24`), which is brute-forceable.

2) **Deterministic nonce from plaintext**
- `nonce_gen` is `sha256(plaintext)[:12]`.
- Same plaintext => same nonce, enabling easy offline guessing and equality leaks.

3) **Broadcast + client-side filtering**
- The server broadcasts messages to everyone; clients drop if `recipient` != self.
- This lets me capture all ciphertexts without being Alice or Bob.

4) **Server authentication disabled**
- If `identities/server_public.json` is missing, server signatures are ignored.
- This weakens authenticity but was not needed for the passive decryption path.

## Exploit Strategy
1) Capture intercepted messages printed by the modified client.
2) For each payload, brute-force the 24-bit chain key seed.
3) Use AES-GCM tag verification to identify the correct key and decrypt.

Because the message key for `n` is derived as `mk = CK + (n + 1)`, once I recover
one message key in a chain, I can derive subsequent keys cheaply.

## Tooling
I implemented a brute-force script that reads intercepted log lines from a file
and decrypts each message as soon as it finds a valid key.

Path: `client/bruteforce_gcm.py`

### Usage
Put intercepted lines in a file (one per line), e.g. `client/intercepts.txt`:

```text
[INTERCEPTED] Message from Bob to Alice: {'type': 'RATCHET', 'header': {'dh': 'fMrkZR/yU/nDm808baB+26xHyP0Kcoxv4I2yWUZ11ik=', 'pn': 1, 'n': 0}, 'ciphertext': 'Jsmm4PBMSqDJY+vbKESpTJIBNQw=', 'nonce': 'SSbo1y6AkXRMNZQv', 'tag': 'lUfLDCwdeZ42QHbUBHe2sA==', 'recipient': 'Alice'}
```

Run:

```bash
python3 client/bruteforce_gcm.py client/intercepts.txt
```

Example output:

```text
[line 2] I love cryptography.
```

## Why It Works
- AES-GCM rejects invalid keys via tag check, so a valid decryption is a clear
  signal that the brute-force guess is correct.
- A 24-bit key space is small enough to brute-force quickly on a laptop.
- Deterministic nonces expose repeated messages and make plaintext guessing easy
  even without keys.

## Flag
We found the following flag after decrypting the intercepted messages.

`CRYPTO-CTF{S1gn4l_Gr0up_Ch4t_h45_f0rw4rd_5ecur17y}`

## Notes
- This is a client-side cryptographic failure, not a break of X25519 or AES-GCM.
- Fixing `KDF_RK` and using random nonces would stop the brute-force path.
