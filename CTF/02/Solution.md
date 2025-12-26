# Christmas Traditions - Writeup
The script `encrypt_decrypt.py` implements a monoalphabetic substitution cipher. It uses a permutation created by generate_perm.py that maps the set of characters `abcdefghijklmnopqrstuvwxyz \n ` to `abcdefghijklmnopqrstuvwxyz01`. This means that every letter, space, and newline in the original text has been replaced by a unique character from the set of lowercase letters and the digits 0 and 1.

## Decrypting the Sample Text

The file `enc_text.txt` contains a long encrypted string. By performing frequency analysis and looking for patterns, we can identify that the plaintext corresponds to the lyrics of the traditional English Christmas carol `Tomorrow shall be my dancing day`.

For example, the first few segments of the encrypted text map as follows:

    xdwduudo → tomorrow

    cagkzz → shall

    crbc → be

    wj → my

    cik0vs0l → dancing

    cikj → day

From this, we can derive the following character mapping:

| Encrypted	| Plaintext |
| --------- | --------- |
| x | t |
| d | o |
| w | m |
| u | r |
| o | w |
| c | (space) |
| a | s |
| g | h |
| k | a |
| z | l |
| r | b |
| b | e |
| j | y |
| i | d |
| 0 | n |
| v | c |
| s | i |
| l | g |
| m | (newline) |
| h | f |
| t | p |
| f | v |


## Decrypting the Flag

Using the mapping derived above, we can decrypt the content of `enc_flag.txt`, which is `fbujvddzk0ibtsvoshstkaaodui`:

    fbuj: v e r y

    vddz: c o o l

    k0i: a n d

    btsv: e p i c

    oshs: w i f i

    tkaadoui: p a s s w o r d

The decrypted string is: `verycoolandepicwifipassword`.

### Final Flag: `CRYPTO_CTF{verycoolandepicwifipassword}`