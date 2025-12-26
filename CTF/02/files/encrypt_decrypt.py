# Define the substitution alphabet
from enc_alphabet import encryption_alphabet


def replace_with_permutation(text, permutation):
    result = []
    for char in text:
        if char in permutation:
            result.append(permutation[char])
        elif char.isalpha() and char.isupper():
            result.append(permutation[char.lower()])
        else:
            result.append(char)
    return ''.join(result)

def encrypt(input_file, output_file):
    with open(input_file, 'r') as infile:
        src_text = infile.read()

    enc_text = replace_with_permutation(src_text, encryption_alphabet)

    with open(output_file, 'w') as outfile:
        outfile.write(enc_text)

    print(f"The encrypted text has been written to '{output_file}'.")

def decrypt(input_file, output_file):
    with open(input_file, 'r') as infile:
        enc_text = infile.read()

    reversed_alphabet = {v: k for k, v in encryption_alphabet.items()}
    dec_text = replace_with_permutation(enc_text, reversed_alphabet)

    with open(output_file, 'w') as outfile:
        outfile.write(dec_text)

    print(f"The decrypted text has been written to '{output_file}'.")

def solve_text():
    src_file = "../files/src_text.txt"
    enc_file = "../files/enc_text.txt"
    dec_file = "../files/dec_text.txt"

    encrypt(src_file, enc_file)
    decrypt(enc_file, dec_file)

def solve_flag():
    src_file = "../files/src_flag.txt"
    enc_file = "../files/enc_flag.txt"
    dec_file = "../files/dec_flag.txt"

    encrypt(src_file, enc_file)
    decrypt(enc_file, dec_file)

if __name__ == '__main__':
    solve_text()
    solve_flag()