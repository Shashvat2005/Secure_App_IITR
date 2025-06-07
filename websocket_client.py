from websocket import WebSocketApp
import threading
from crypto import CryptoHandler

class WebSocketClient:
    def __init__(self, url, message_queue, status_callback, key_callback, topic):
        self.url = url
        self.message_queue = message_queue
        self.status_callback = status_callback
        self.key_callback = key_callback
        self.topic = topic
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
            
            elif message.startswith("g:"):
                self.crypto.g = int(message[2:].strip())
                public_key = self.crypto.generate_public_key(self.crypto.p, self.crypto.g)
                ws.send(f"start-dh:{str(public_key)}")

            elif message.startswith("dh-server-pub:"):
                server_pub_key = int(message[14:].strip())
                shared_key, aes_iv = self.crypto.generate_shared_secret(
                    self.crypto.p, server_pub_key
                )
                # Notify UI about new keys
                self.key_callback(
                    shared_key.hex() if shared_key else None,
                    aes_iv.hex() if aes_iv else None
                )
                self.message_queue.put("[Key Exchange Successful]")
                
                # Subscribe to user-specified topic
                ws.send(f"subscribe:{self.topic}")

            elif message.startswith("data:"):
                decrypted = self.crypto.decrypt_aes_128_cbc(message[5:].strip())
                self.message_queue.put(f"[Decrypted]: {decrypted}")
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