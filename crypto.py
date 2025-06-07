import hashlib
import secrets
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CryptoHandler:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.aes_iv = None
        self.p = None
        self.g = None

    def pow_dh(self, base, exponent, modulus):
        """Efficient modular exponentiation"""
        return pow(base, exponent, modulus)

    def generate_public_key(self, p, g):
        """Generate public key using DH parameters"""
        self.private_key = secrets.randbits(256)
        self.public_key = self.pow_dh(g, self.private_key, p)
        return self.public_key

    def generate_shared_secret(self, p, server_public_key):
        """Generate shared secret from server's public key"""
        shared_key_unhash = self.pow_dh(server_public_key, self.private_key, p)
        shared_key_bytes = shared_key_unhash.to_bytes(
            (shared_key_unhash.bit_length() + 7) // 8, 
            byteorder='big'
        )
        shared_key_hashed = hashlib.sha256(shared_key_bytes).digest()
        
        self.shared_key = shared_key_hashed[:16]
        self.aes_iv = shared_key_hashed[16:]
        return self.shared_key, self.aes_iv

    def decrypt_aes_128_cbc(self, ciphertext_b64):
        """Decrypt AES-128-CBC encrypted message"""
        try:
            ciphertext = b64decode(ciphertext_b64)
            key = self.shared_key
            iv = self.aes_iv
            
            if not key or not iv:
                raise ValueError("Encryption keys not established")
                
            cipher = Cipher(
                algorithms.AES(key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")