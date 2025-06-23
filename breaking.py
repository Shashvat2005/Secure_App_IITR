import itertools
from itertools import permutations
import base64
import math
import re



def vigenere_decrypt(cipher_text, key):
    cipher_text = cipher_text.upper()
    key = key.upper()
    plaintext = ''
    key_index = 0

    for i in range(len(cipher_text)):
        c = cipher_text[i]
        if c.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            p = chr(((ord(c) - ord('A') - shift + 26) % 26) + ord('A'))
            plaintext += p
            key_index += 1
        else:
            plaintext += c

    return plaintext


def decrypt_transposition(cipher_text, key):
    """Decrypts message using keyword-based columnar transposition cipher"""
    import math

    key = key.upper()
    num_cols = len(key)
    num_rows = math.ceil(len(cipher_text) / num_cols)

    # Create key order map based on alphabetical order
    key_order = sorted([(char, i) for i, char in enumerate(key)])
    sorted_key_indices = [index for _, index in key_order]

    # Calculate number of shaded boxes in the last row
    num_shaded = (num_cols * num_rows) - len(cipher_text)

    # Create empty columns based on sorted key order
    columns = [''] * num_cols
    col_lengths = [num_rows] * num_cols
    for i in sorted_key_indices[::-1]:
        if num_shaded > 0:
            col_lengths[i] -= 1
            num_shaded -= 1

    # Fill the columns with ciphertext
    index = 0
    for k in sorted_key_indices:
        length = col_lengths[k]
        columns[k] = cipher_text[index:index + length]
        index += length

    # Reconstruct the original message row-wise
    plaintext = ''
    for row in range(num_rows):
        for col in range(num_cols):
            if row < len(columns[col]):
                plaintext += columns[col][row]

    for i in plaintext:
        plaintext = plaintext.rstrip('X')

    return plaintext


def break_caesar(ciphertext):
    possibilities = []
    for shift in range(26):
        decrypted = ""
        for char in ciphertext:
            if char.isupper():
                decrypted += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            elif char.islower():
                decrypted += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            elif char.isdigit():
                decrypted += chr((ord(char) - ord('0') - shift) % 10 + ord('0'))
            else:
                decrypted += char
        possibilities.append((shift, decrypted))
    return possibilities

def brute_force_vigenere(ciphertext, max_key_length=3):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for length in range(1, max_key_length + 1):
        for key_tuple in itertools.product(charset, repeat=length):
            key = ''.join(key_tuple)
            print(f"Trying key: {key}")
            print(vigenere_decrypt(ciphertext, key))

def brute_force_transposition(ciphertext, key_length):
    import string
    chars = string.ascii_uppercase[:key_length]
    for key in permutations(chars):
        key_str = ''.join(key)
        print(f"Trying key: {key_str}")
        try:
            print(decrypt_transposition(ciphertext, key_str))
        except:
            continue



def brute_force_vigenere_full(ciphertext, max_len=2):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789."
    char_len = len(charset)

    def decrypt(ciphertext, key):
        decrypted = []
        key_index = 0
        for c in ciphertext:
            if c in charset:
                c_idx = charset.index(c)
                k = key[key_index % len(key)]
                k_idx = charset.index(k)
                decrypted_char = charset[(c_idx - k_idx) % char_len]
                decrypted.append(decrypted_char)
                key_index += 1
            else:
                decrypted.append(c)
        return ''.join(decrypted)

    all_results = []
    for key_len in range(1, max_len + 1):
        for key_tuple in itertools.product(charset, repeat=key_len):
            key = ''.join(key_tuple)
            plain = decrypt(ciphertext, key)
            all_results.append((key, plain))
            print(f"[KEY: {key}] → {plain[:80]}")  # Print partial result
    return all_results



def brute_force_transposition_base64(cipher_b64, max_key_len=6):
    def filter_alphanumeric(s):
        return re.sub(r'[^A-Za-z0-9.]', '', s)

    def decrypt_transposition(cipher_text, key):
        key = key.upper()
        num_cols = len(key)
        num_rows = math.ceil(len(cipher_text) / num_cols)

        key_order = sorted([(char, i) for i, char in enumerate(key)])
        sorted_key_indices = [index for _, index in key_order]

        num_shaded = (num_cols * num_rows) - len(cipher_text)

        columns = [''] * num_cols
        col_lengths = [num_rows] * num_cols
        for i in sorted_key_indices[::-1]:
            if num_shaded > 0:
                col_lengths[i] -= 1
                num_shaded -= 1

        index = 0
        for k in sorted_key_indices:
            length = col_lengths[k]
            columns[k] = cipher_text[index:index + length]
            index += length

        plaintext = ''
        for row in range(num_rows):
            for col in range(num_cols):
                if row < len(columns[col]):
                    plaintext += columns[col][row]
        return plaintext.rstrip('X')

    try:
        cipher_text = base64.b64decode(cipher_b64).decode()
    except:
        print("Invalid base64 input")
        return

    cipher_text = filter_alphanumeric(cipher_text)

    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for key_len in range(2, max_key_len + 1):
        for key_perm in itertools.permutations(charset[:key_len]):
            key = ''.join(key_perm)
            try:
                plaintext = decrypt_transposition(cipher_text, key)
                print(f"[KEY: {key}] → {plaintext[:80]}")
            except Exception:
                continue

def breaking(text):
    for shift in range(101):
        result = ""
        for char in text:
            if char.isupper():
                shift_base = ord('A')
                result += chr((ord(str(char)) - shift_base - shift) % 26 + shift_base)
            elif char.islower():
                shift_base = ord('a')
                result += chr((ord(str(char)) - shift_base - shift) % 26 + shift_base)
            elif char.isdigit():
                shift_base = ord('0')
                result += chr((ord(str(char)) - shift_base - shift) % 10 + shift_base)
            else:
                result += char
                continue
        print(f"shift value: {shift}: ",result)



print(breaking("nkzzy: 4738"))

