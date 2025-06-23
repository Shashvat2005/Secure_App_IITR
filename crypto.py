import hashlib
import secrets
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import re
import math
import base64

class CryptoHandler:
    def __init__(self):
        self.private_key = None # Private key for Diffie-Hellman
        self.public_key = None  # Public key for Diffie-Hellman
        self.shared_key = None  # Shared secret key derived from Diffie-Hellman
        self.aes_iv = None      # Initialization vector for AES
        self.p = None           # Prime number for Diffie-Hellman
        self.g = None           # Generator for Diffie-Hellman
        self.cipher = None      # AES cipher object

    def pow_dh(self, base, exponent, modulus):
        """Efficient modular exponentiation"""
        return pow(base, exponent, modulus) 

    def generate_public_key(self, p, g):
        """Generate public key using DH parameters"""
        self.private_key = secrets.randbits(256) # Generate a random private key
        self.public_key = self.pow_dh(g, self.private_key, p) # Diffie-Hellman public key
        return self.public_key

    def generate_shared_secret(self, p, server_public_key):
        """Generate shared secret from server's public key"""
        shared_key_unhash = self.pow_dh(server_public_key, self.private_key, p) # Diffie-Hellman shared secret
        # Convert shared key to bytes and hash it to derive AES key and IV
        shared_key_bytes = shared_key_unhash.to_bytes( 
            (shared_key_unhash.bit_length() + 7) // 8, 
            byteorder='big'
        )
        shared_key_hashed = hashlib.sha256(shared_key_bytes).digest() # Hash the shared key to get a fixed-length key
        
        self.shared_key = shared_key_hashed[:16] # Use first 16 bytes for AES-128 key
        self.aes_iv = shared_key_hashed[16:] # Use next 16 bytes for AES IV

        # Initialize AES cipher in CBC mode with the derived key and IV
        self.cipher = Cipher(
                algorithms.AES(self.shared_key), 
                modes.CBC(self.aes_iv), 
                backend=default_backend()
            ) 
        
        return self.shared_key, self.aes_iv

    def decrypt_aes_128_cbc(self, ciphertext_b64):
        """Decrypt AES-128-CBC encrypted message"""
        try:
            ciphertext = b64decode(ciphertext_b64) # Decode base64 ciphertext
            key = self.shared_key # AES key derived from Diffie-Hellman
            iv = self.aes_iv    # AES IV derived from Diffie-Hellman
            
            if not key or not iv:
                raise ValueError("Encryption keys not established")
                
            decryptor = self.cipher.decryptor() # Create AES decryptor
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize() # Finalize decryption
            
            unpadder = padding.PKCS7(128).unpadder() # Create unpadder for PKCS7 padding
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize() # Remove padding
            
            return plaintext.decode('utf-8') # Return decrypted plaintext as string
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        
    def shift_cipher(self, text, shift):
        """Encrypt or decrypt text using Caesar cipher"""
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
            
        return str(result)
    
    def vigenere_decrypt(self, cipher_text, key):
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

    def decrypt_transposition(self, cipher_text, key):
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

    def playfair_decrypt(self, cipher_text, key):
        """Decrypts message using Playfair cipher"""
        key = key.upper().replace("J", "I")
        matrix = []
        used = set()

        # Generate matrix
        for char in key:
            if char not in used and char.isalpha():
                used.add(char)
                matrix.append(char)
        for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if char not in used:
                used.add(char)
                matrix.append(char)
        matrix = [matrix[i:i + 5] for i in range(0, 25, 5)]

        def find(char):
            for r in range(5):
                for c in range(5):
                    if matrix[r][c] == char:
                        return r, c

        # Decrypt cipher_text
        plaintext = ""
        cipher_text = cipher_text.upper().replace("J", "I")
        for i in range(0, len(cipher_text), 2):
            a, b = cipher_text[i], cipher_text[i + 1]
            r1, c1 = find(a)
            r2, c2 = find(b)
            if r1 == r2:
                plaintext += matrix[r1][(c1 - 1) % 5]
                plaintext += matrix[r2][(c2 - 1) % 5]
            elif c1 == c2:
                plaintext += matrix[(r1 - 1) % 5][c1]
                plaintext += matrix[(r2 - 1) % 5][c2]
            else:
                plaintext += matrix[r1][c2]
                plaintext += matrix[r2][c1]

        # Post-processing to remove padding X
        cleaned = ""
        i = 0
        while i < len(plaintext):
            a = plaintext[i]
            if i + 2 < len(plaintext) and plaintext[i + 1] == 'X' and plaintext[i] == plaintext[i + 2]:
                cleaned += a
                i += 2  # skip the inserted 'X'
            else:
                cleaned += a
                i += 1
        # Remove trailing X if it was just padding
        if cleaned.endswith("X"):
            cleaned = cleaned[:-1]

        return cleaned

    # These implementations handle alpha-numeric data in decryption for various ciphers

    def vigenere_decrypt_full(self, ciphertext, key):
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789."
        char_len = len(charset)

        filtered_key = []
        key_index = 0

        for c in ciphertext:
            if c in charset:
                filtered_key.append(key[key_index % len(key)])
                key_index += 1
            else:
                filtered_key.append(None)

        decrypted = []

        for c, k in zip(ciphertext, filtered_key):
            if c in charset and k is not None:
                c_idx = charset.index(c)
                k_idx = charset.index(k) if k in charset else charset.index(k.upper())
                decrypted_char = charset[(c_idx - k_idx) % char_len]
                decrypted.append(decrypted_char)
            else:
                decrypted.append(c)

        return ''.join(decrypted)

    def transposition_decrypt_base64(self, cipher_b64, key):
        def filter_alphanumeric(s):
            return re.sub(r'[^A-Za-z0-9.]', '', s)

        def get_key_order(k):
            indexed = list(enumerate(k))
            sorted_key = sorted(indexed, key=lambda x: (x[1], x[0]))
            order = [i for i, _ in sorted_key]
            return order

        cipher_text = base64.b64decode(cipher_b64).decode()
        cipher_text = filter_alphanumeric(cipher_text)
        key = filter_alphanumeric(key)

        num_cols = len(key)
        num_rows = math.ceil(len(cipher_text) / num_cols)

        key_order = get_key_order(key)

        col_pos_map = [0] * num_cols
        for sorted_pos, original_index in enumerate(key_order):
            col_pos_map[original_index] = sorted_pos

        grid = [[''] * num_cols for _ in range(num_rows)]
        k = 0
        for col_sorted_index in range(num_cols):
            col = key_order[col_sorted_index]
            for row in range(num_rows):
                if k < len(cipher_text):
                    grid[row][col] = cipher_text[k]
                    k += 1

        plaintext = ''.join(grid[r][c] for r in range(num_rows) for c in range(num_cols))

        return plaintext.rstrip('X')

    def decrypt_playfair_full(self, ciphertext, key):
        import string

        def generate_matrix(key):
            charset = string.ascii_uppercase + "0123456789"
            key = ''.join([c for c in key.upper() if c in charset])
            used = set()
            matrix_key = []

            for c in key:
                if c not in used:
                    matrix_key.append(c)
                    used.add(c)

            for c in charset:
                if c not in used:
                    matrix_key.append(c)
                    used.add(c)

            matrix = [matrix_key[i*6:(i+1)*6] for i in range(6)]
            return matrix

        def find_position(matrix, char):
            for i in range(6):
                for j in range(6):
                    if matrix[i][j] == char:
                        return i, j
            return None

        def remove_padding(text):
            result = []
            i = 0
            while i < len(text):
                if (i < len(text) - 2 and text[i] == text[i+2] and text[i+1] == 'X'):
                    result.append(text[i])
                    i += 2
                else:
                    result.append(text[i])
                    i += 1
            if result and result[-1] == 'X':
                result.pop()
            return ''.join(result)

        matrix = generate_matrix(key)
        plaintext = []

        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i+1]
            row_a, col_a = find_position(matrix, a)
            row_b, col_b = find_position(matrix, b)

            if row_a == row_b:
                plaintext.append(matrix[row_a][(col_a - 1) % 6])
                plaintext.append(matrix[row_b][(col_b - 1) % 6])
            elif col_a == col_b:
                plaintext.append(matrix[(row_a - 1) % 6][col_a])
                plaintext.append(matrix[(row_b - 1) % 6][col_b])
            else:
                plaintext.append(matrix[row_a][col_b])
                plaintext.append(matrix[row_b][col_a])

        return remove_padding(''.join(plaintext))


