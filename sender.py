import asyncio
import websockets
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.backends import default_backend

# Crypto
def generate_private_key():
    return int.from_bytes(os.urandom(1), "big")

def generate_public_key(private_key, p, g):
    return pow(g, private_key, p)

def generate_shared_secret(peer_public, private, p):
    return pow(peer_public, private, p)

def aes_encrypt(key: int, plaintext: str) -> bytes:
    key_bytes = key.to_bytes(16, 'big')[:16]
    iv = key_bytes
    padder = aes_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

async def sender():
    uri = "ws://localhost:8765"  # Connect to MITM (not directly to receiver)
    async with websockets.connect(uri) as websocket:
        print("[Sender] Connected to MITM")

        # Step 1: Send p, g
        p = 23
        g = 5
        await websocket.send(f"{p},{g}")
        print(f"[Sender] Sent p, g = ({p}, {g})")

        # Step 2: Key exchange
        priv_key = generate_private_key()
        pub_key = generate_public_key(priv_key, p, g)

        # Receive peer public key
        peer_pub = int(await websocket.recv())
        await websocket.send(str(pub_key))
        print(f"[Sender] Key exchange done")

        # Derive AES key
        shared_key = generate_shared_secret(peer_pub, priv_key, p)

        # Step 3: Send encrypted data
        messages = ["hello", "sensor=42", "temp=30", "goodbye"]
        for msg in messages:
            enc = aes_encrypt(shared_key, msg)
            await websocket.send(enc.hex())
            print(f"[Sender] Sent encrypted: {msg}")
            await asyncio.sleep(1)

        print("[Sender] Done sending.")

asyncio.run(sender())
