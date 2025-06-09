from websocket import WebSocketApp
import threading
from crypto import CryptoHandler
import logging

logger = logging.getLogger(__name__)

class WebSocketClient:
    def __init__(self, url, message_queue, status_callback, key_callback, topic1, topic2):
        self.url = url
        self.message_queue = message_queue
        self.status_callback = status_callback
        self.key_callback = key_callback
        self.topic1 = topic1
        self.topic2 = topic2
        self.ws = None
        self.is_connected = False
        self.crypto = CryptoHandler()
        
    def run(self):
        """Start the WebSocket connection"""
        self.ws = WebSocketApp(
            self.url,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
            on_open=self._on_open
        )
        
        try:
            self.ws.run_forever()
        except Exception as e:
            self.message_queue.put(f"[Connection Error] {str(e)}")
            self.status_callback(f"Error: {str(e)}", "#c0392b")
            
    def close(self):
        """Close the WebSocket connection"""
        if self.ws and self.is_connected:
            self.ws.close()
            self.is_connected = False

    def _on_message(self, ws, message):
        """Handle incoming messages"""
        try:
            if message.startswith("p:"):
                self.crypto.p = int(message[2:].strip())
                self.message_queue.put("[Received DH parameter 'p']")
            
            elif message.startswith("g:"):
                self.crypto.g = int(message[2:].strip())
                self.message_queue.put("[Received DH parameter 'g']")
                public_key = self.crypto.generate_public_key(self.crypto.p, self.crypto.g)
                ws.send(f"start-dh:{str(public_key)}")
                self.message_queue.put("[Sent public key for key exchange]")

            elif message.startswith("dh-server-pub:"):
                server_pub_key = int(message[14:].strip())
                self.message_queue.put("[Received server public key]")
                shared_key, aes_iv = self.crypto.generate_shared_secret(
                    self.crypto.p, server_pub_key
                )
                # Notify UI about new keys
                self.key_callback(
                    shared_key.hex() if shared_key else None,
                    aes_iv.hex() if aes_iv else None
                )
                self.message_queue.put("[Key Exchange Successful]")
                
                # Subscribe to both topics
                ws.send(f"subscribe:{self.topic1}")
                ws.send(f"subscribe:{self.topic2}")
                self.message_queue.put(f"[Subscribed to topics: '{self.topic1}', '{self.topic2}']")

            elif message.startswith("data:"):
                # Format: "data: topic <base64-encrypted-data>"
                parts = message.split(" ", 2)
                if len(parts) < 3:
                    self.message_queue.put(f"[ERROR] Invalid message format: {message}")
                    return
                    
                topic_received = parts[1].strip()
                encrypted_data = parts[2].strip()
                
                # Decrypt the message
                decrypted = self.crypto.decrypt_aes_128_cbc(encrypted_data)
                
                # Determine which topic this belongs to
                if topic_received == self.topic1:
                    self.message_queue.put((1, f"{topic_received}: {decrypted}"))
                elif topic_received == self.topic2:
                    self.message_queue.put((2, f"{topic_received}: {decrypted}"))
                else:
                    self.message_queue.put(f"[WARNING] Received message for unknown topic: {topic_received}")
            else:
                self.message_queue.put(f"[Raw Message]: {message}")
        except Exception as e:
            self.message_queue.put(f"[Processing Error] {str(e)}")

    def _on_error(self, ws, error):
        self.message_queue.put(f"[WebSocket Error] {error}")
        self.status_callback(f"Error: {error}", "#c0392b")

    def _on_close(self, ws, close_status_code, close_msg):
        self.is_connected = False
        self.message_queue.put(f"[Connection Closed] Code: {close_status_code}, Message: {close_msg}")
        self.status_callback("Disconnected", "#7f8c8d")

    def _on_open(self, ws):
        self.is_connected = True
        self.message_queue.put("[Connected to WebSocket Server]")
        self.status_callback("Connected", "#27ae60")