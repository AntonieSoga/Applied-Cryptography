from collections import Counter

def analyze_frequencies(file_path):
    try:
        with open(file_path, 'r') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return

    # 1. Individual Character Frequency
    total_chars = len(ciphertext)
    char_counts = Counter(ciphertext)
    
    print(f"--- Character Frequency Analysis (Total: {total_chars}) ---")
    print(f"{'Char':<6} | {'Count':<6} | {'Percentage':<10}")
    print("-" * 30)
    
    # Sort by frequency descending
    for char, count in char_counts.most_common():
        percentage = (count / total_chars) * 100
        display_char = char.replace('\n', '\\n')  # Make newline visible
        print(f"{display_char:<6} | {count:<6} | {percentage:>8.2f}%")

    # 2. N-Gram Analysis (Patterns)
    print("\n--- Common N-Grams ---")
    
    def get_ngrams(text, n):
        return [text[i:i+n] for i in range(len(text)-n+1)]

    for n in [2, 3, 4]:
        ngrams = get_ngrams(ciphertext, n)
        common_ngrams = Counter(ngrams).most_common(10)
        print(f"\nTop {n}-grams:")
        for pattern, count in common_ngrams:
            display_pattern = pattern.replace('\n', '\\n')
            print(f"  {display_pattern}: {count}")

if __name__ == "__main__":
    analyze_frequencies(r"CTF\02\files\enc_text.txt")