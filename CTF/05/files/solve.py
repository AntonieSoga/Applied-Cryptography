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
        print(f"{n} {h} -> {content}")