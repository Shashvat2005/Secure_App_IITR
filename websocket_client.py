from websocket import WebSocketApp
from crypto import CryptoHandler
import logging
import csv
import time as t
from base64 import b64decode

logger = logging.getLogger(__name__)

Topic1 = None
Topic2 = None
flag1 = False
flag2 = False

class WebSocketClient:
    def __init__(self, url, message_queue, status_callback, key_callback, cipher_var):
        self.url = url
        self.message_queue = message_queue
        self.status_callback = status_callback
        self.key_callback = key_callback
        self.ws = None
        self.is_connected = False
        self.crypto = CryptoHandler()
        self.topic1 = None
        self.topic2 = None
        self.file = None  # File object
        self.writer = None  # CSV writer object
        self.type_of_encryption = None  # Type of encryption used
        self.cipher_shift = None  # Shift value for Caesar cipher 
        self.decryption_key = None  # Key for Vigenère cipher or other encryption methods
        self.id = None  # Unique identifier for the client, if needed
        self.password = None  # Password for authentication, if needed
        self.cipher_var = cipher_var

    def log_data(self, data:str):
        """
        Log data to a CSV file
        data: The data to log
        """
        if self.file and self.writer: # Check if file and writer are initialized
            # Log the data into the CSV file
            time1 = t.time() # Get the current time
            try:
                row = [time1] + list(data) # Create a row with the current time and data
                self.writer.writerow(row) # Write the row to the CSV file
            except ValueError as e:
                pass
        else:
            logger.error("File or writer not initialized for logging.")   

    def subscribe(self, topic, no): # Handle Subscription to multiple topics
        """
        Subscribe to a topic
        topic: The topic to subscribe to
        no: The topic number (1 or 2) to determine which topic to subscribe to
        """
        global Topic1, Topic2, flag1, flag2                 # Global variables to track topics and flags

        # self.id = input("Enter the ID:")                  # Take ID from the user before subscription
        # self.password = input("Enter the Password:")      # Take Password from the user before subscription

        self.id = 'test1'           # Default ID for testing
        self.password = 'test1'     # Default Password for testing

        # Subscription for Topic 1
        if no == 1:
            self.topic1 = topic # Assign topic to topic1 variable of class
            if flag1 and Topic2 != topic: # If already subscribed to Topic 2 and trying to subscribe to Topic 1
                self.ws.send(f"unsubscribe:{Topic1}") # Unsubscribe from Topic 1
                self.message_queue.put((no, f"[Unsubscribed to topic: '{Topic1}']")) # Show unsubscribe message
                #print(f"Unsubscribed to topic 1: {Topic1}")  # Debug message for unsubscription

                if topic: # Check if a new topic is provided
                    self.ws.send(f"subscribe:{topic} {self.id} {self.password}") # Subscribe to new topic
                    self.message_queue.put((no, f"[Subscribed to topic: '{topic}']")) # Show subscribe message
                    print(f"Subscribed to topic: {topic}") # Debug message for subscription
                    flag1 = True # Set flag1 to True indicating subscription to Topic 1
                    Topic1 = topic  # Update Topic1 with the new topic
                else:
                    self.message_queue.put((no, "[ERROR] No topic provided for subscription")) # Show error message if no topic is provided
                    
            elif flag2 and Topic2 == topic: # If already subscribed to Topic 1 and trying to subscribe to Topic 2
                self.message_queue.put((1,f"[ERROR] Cannot subscribe to the same topic twice: {topic}")) # Show error message if trying to subscribe to the same topic again
            elif not flag1: # If not already subscribed to Topic 1
                if topic: # Check if a topic is provided
                    self.ws.send(f"subscribe:{topic} {self.id} {self.password}") # Subscribe to the topic
                    self.message_queue.put((no, f"[Subscribed to topic: '{topic}']")) # Show subscribe message
                    print(f"Subscribed to topic: {topic}") # Debug message for subscription
                    flag1 = True # Set flag1 to True indicating subscription to Topic 1
                    Topic1 = topic # Update Topic1 with the new topic
                else:
                    self.message_queue.put((no, "[ERROR] No topic provided for subscription")) # Show error message if no topic is provided
            
        # Subscription for Topic 2
        elif no == 2:
            self.topic2 = topic # Assign topic to topic2 variable of class
            if flag2 and Topic1 != topic: # If already subscribed to Topic 1 and trying to subscribe to Topic 2
                self.ws.send(f"unsubscribe:{Topic2}") # Unsubscribe from Topic 2
                print(f"Unsubscribed to topic 2: {Topic2}") # Debug message for unsubscription
                self.message_queue.put((no, f"[Unsubscribed to topic: '{Topic2}']")) # Show unsubscribe message
                if topic: # Check if a new topic is provided
                    self.ws.send(f"subscribe:{topic} {self.id} {self.password}") # Subscribe to new topic
                    self.message_queue.put((no, f"[Subscribed to topic: '{topic}']")) # Show subscribe message
                    print(f"Subscribed to topic: {topic}") # Debug message for subscription
                    flag2 = True # Set flag2 to True indicating subscription to Topic 2
                    Topic2 = topic # Update Topic2 with the new topic
                else: 
                    self.message_queue.put((no, "[ERROR] No topic provided for subscription")) # Show error message if no topic is provided
            elif flag1 and Topic1 == topic: # If already subscribed to Topic 2 and trying to subscribe to Topic 1
                self.message_queue.put((2,f"[ERROR] Cannot subscribe to the same topic twice: {topic}")) # Show error message if trying to subscribe to the same topic again
                
            elif not flag2: # If not already subscribed to Topic 2
                if topic: # Check if a topic is provided
                    self.ws.send(f"subscribe:{topic} {self.id} {self.password}") # Subscribe to the topic
                    self.message_queue.put((no, f"[Subscribed to topic: '{topic}']")) # Show subscribe message
                    print(f"Subscribed to topic: {topic}") # Debug message for subscription
                    flag2 = True    # Set flag2 to True indicating subscription to Topic 2
                    Topic2 = topic # Update Topic2 with the new topic
                else:
                    self.message_queue.put((no, "[ERROR] No topic provided for subscription")) # Show error message if no topic is provided
        
 
        if not self.is_connected: # Check if the WebSocket is connected
            self.message_queue.put("[ERROR] Not connected to WebSocket server")     # Show error message if not connected
            return # Exit the function if not connected
        
    def run(self): #Run the websocket connection
        """Start the WebSocket connection"""
        try:
            # Open the file once when the connection starts
            self.file = open('/Users/shashvatgarg/Desktop/Shashvat_Garg/Intern_IITR/SecureChat/shared/data.csv', 'a', newline='')
            self.writer = csv.writer(self.file)
            # Write header if the file is empty
            

            self.ws = WebSocketApp( 
                self.url, # WebSocket server URL
                on_message=self._on_message, # Callback for incoming messages
                on_error=self._on_error, # Callback for errors
                on_close=self._on_close, # Callback for connection close
                on_open=self._on_open # Callback for connection open
            )

            self.ws.run_forever() # Start the WebSocket connection and keep it open
            
        except Exception as e:
            self.message_queue.put(f"[Connection Error] {str(e)}") # Show connection error message
            self.status_callback(f"Error: {str(e)}", "#c0392b") # Update status callback with error message
        finally:
            # Ensure the file is closed if an error occurs
            if self.file:
                self.file.close()

    def close(self): #Close the websocket connection
        """Close the WebSocket connection and the file"""
        if self.ws and self.is_connected: # Check if WebSocket is connected
            self.ws.close() # Close the WebSocket connection
            self.is_connected = False # Update connection status
        if self.file: # Check if the file is open
            self.file.close() # Close the file to ensure data is saved

    def _on_message(self, ws, message): # Handle incoming messages
        """Handle incoming messages"""
        global Topic2, Topic1 # Global variables to track topics

        # login in try block to handle errors gracefully
        try:
            if message.startswith("type:"):
                # Format: "type: <type of encryption>"
                self.type_of_encryption = message[5:].strip() # Extract type of encryption
                #print(f"Type of encryption: {self.type_of_encryption}") # Debug message for type of encryption

            if self.type_of_encryption == "1": #Shift cipher
                if message.startswith("shift:"):
                    # Format: "shift: <shift value>"
                    self.cipher_shift = int(message[6:].strip()) # Extract shift value
                    self.message_queue.put(f"[Received Caesar cipher shift value: {self.cipher_shift}]") # Show message for received shift value
                elif message.startswith("data:"):
                    parts = message.split(" ", 2) # Split the message into parts
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}") # Show error message if the message format is invalid
                        return # Exit the function if the message format is invalid
                    
                    encrypted_data = parts[2].strip() # Extract encrypted data from the message
                    print("Encrypted Message:", encrypted_data) # Debug message for encrypted data

                    # Decrypt the message using Caesar cipher
                    decrypted = self.crypto.shift_cipher(str(b64decode(encrypted_data).decode('utf-8')).strip(), self.cipher_shift) # Decrypt the message using Caesar cipher
                    #self.message_queue.put((1, f"[Decrypted message: {decrypted}]"))
                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]"))
                    #print(f"Decrypted message: {decrypted}") # Debug message for decrypted message

                    # Write data into file
                    #self.log_data(decrypted)
            
            elif self.type_of_encryption == "2": # AES

                if message.startswith("p:"):
                    self.crypto.p = int(message[2:].strip()) # Extract DH parameter 'p'
                    self.message_queue.put("[Received DH parameter 'p']") # Show message for received DH parameter 'p'
                
                elif message.startswith("g:"):
                    self.crypto.g = int(message[2:].strip()) # Extract DH parameter 'g'
                    self.message_queue.put("[Received DH parameter 'g']") # Show message for received DH parameter 'g'
                    public_key = self.crypto.generate_public_key(self.crypto.p, self.crypto.g) # Generate Public Key
                    ws.send(f"start-dh:{str(public_key)}") # Send Public key
                    self.message_queue.put("[Sent public key for key exchange]") # Show message for public key sent

                elif message.startswith("dh-server-pub:"):
                    server_pub_key = int(message[14:].strip()) # Extract Server Public Key
                    self.message_queue.put("[Received server public key]") # Send message for public key received
                    shared_key, aes_iv = self.crypto.generate_shared_secret(
                        self.crypto.p, server_pub_key   # Generate shared key and iv
                    )
                    # Notify UI about new keys
                    self.key_callback(
                        shared_key.hex() if shared_key else None, # Convert shared key to hex format
                        aes_iv.hex() if aes_iv else None # Convert AES IV to hex format
                    )
                    self.message_queue.put("[Key Exchange Successful]") # Show message for key exchange successful

                elif message.startswith("data:"): 
                    # Format: "data: topic <base64-encrypted-data>"
                    parts = message.split(" ", 2) # Split the message into parts
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}") # Show error message if the message format is invalid
                        return # Exit the function if the message format is invalid
                
                    encrypted_data = parts[2].strip() # Extract encrypted data from the message
                    print("Encrypted Message:", encrypted_data)  # Debug message for encrypted data
                    
                    decrypted = self.crypto.decrypt_aes_128_cbc(encrypted_data) # Decrypt the message using AES 128 CBC

                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]")) 

                    self.log_data(decrypted) # Write data into file
                else:
                    self.message_queue.put(f"[Raw Message]: {message}")
            
            elif self.type_of_encryption == "3": # Vigenere cipher
                if message.startswith("VCKey:"):
                    # Format: "key: <encryption key>"
                    self.decryption_key = message[6:].strip() # Extract Vigenère cipher key
                    self.message_queue.put(f"[Received Vigenère cipher key: {self.decryption_key}]") # Show message for received Vigenère cipher key
                elif message.startswith("data:"): 
                    parts = message.split(" ", 2) # Split the message into parts
                    if len(parts) < 3: 
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}") # Show error message if the message format is invalid
                        return
                    
                    encrypted_data = parts[2].strip() # Extract encrypted data from the message
                    
                    print(f"Encrypted data: {encrypted_data}")  # Debug message for encrypted data

                    # Decrypt the message using Vigenère cipher
                    decrypted = self.crypto.vigenere_decrypt(str(b64decode(encrypted_data).decode('utf-8')).strip(), self.decryption_key)

                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]")) 
                    
                    self.log_data(decrypted)
            
            elif self.type_of_encryption == "4": # Transposition cipher
                if message.startswith("TCKey:"): 
                    # Format: "key: <encryption key>"
                    self.decryption_key = message[6:].strip() # Get the Transposition cipher key
                    self.message_queue.put(f"[Received Transposition cipher key: {self.decryption_key}]") # Show message for received Transposition cipher key

                elif message.startswith("data:"): 
                    parts = message.split(" ", 2) # Split the message into parts
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}") # Show error message if the message format is invalid
                        return # Exit the function if the message format is invalid
                    
                    encrypted_data = parts[2].strip() # Extract encrypted data from the message
                    print(f"Encrypted data: {encrypted_data}")  # Debug message for encrypted data

                    # Decrypt the message using Transposition cipher
                    decrypted = self.crypto.decrypt_transposition(str(b64decode(encrypted_data).decode('utf-8')).strip(), self.decryption_key)
                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]"))
                    #print(f"Decrypted message: {decrypted}")
                    # Write data into file
                    self.log_data(decrypted)

            elif self.type_of_encryption == "5": # Playfair cipher
                if message.startswith("PFCKey:"):
                    # Format: "key: <encryption key>"
                    self.decryption_key = message[7:].strip()
                    self.message_queue.put(f"[Received Playfair cipher key: {self.decryption_key}]")
                elif message.startswith("data:"):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}")
                        return
                    #self.decryption_key = self.crypto.dh_key_to_string(self.decryption_key, 6)  # Ensure key is in string format
                    encrypted_data = parts[2].strip()
                    print(f"Encrypted data: {encrypted_data}")

                    # Decrypt the message using Playfair cipher
                    decrypted = self.crypto.playfair_decrypt(str(b64decode(encrypted_data).decode('utf-8')).strip(), self.decryption_key)

                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]"))

                    #print(f"Decrypted message: {decrypted}")
                    # Write data into file
                    self.log_data(decrypted)
        
            elif self.type_of_encryption == "6": # Vigenère cipher full
                if message.startswith("VCAKey:"):
                    # Format: "key: <encryption key>"
                    self.decryption_key = message[7:].strip()
                    self.message_queue.put(f"[Received Vigenère cipher full key: {self.decryption_key}]")
                elif message.startswith("data:"):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}")
                        return
                    
                    encrypted_data = parts[2].strip()
                    print(f"Encrypted data: {encrypted_data}")  # Debug message for encrypted data
                    decrypted = self.crypto.vigenere_decrypt_full(str(b64decode(encrypted_data).decode('utf-8')).strip(), self.decryption_key)
                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]"))
                    #print(f"Decrypted message: {decrypted}")
                    # Write data into file
                    self.log_data(decrypted)
        
            elif self.type_of_encryption == "7": # Transposition cipher full
                if message.startswith("TCAKey:"):
                    # Format: "key: <encryption key>"
                    self.decryption_key = message[7:].strip()
                    self.message_queue.put(f"[Received Transposition cipher key: {self.decryption_key}]")

                elif message.startswith("data:"):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}")
                        return
                    
                    encrypted_data = parts[2].strip()
                    print(f"Encrypted data: {encrypted_data}")  # Debug message for encrypted data
                    decrypted = self.crypto.transposition_decrypt_base64(str(encrypted_data).strip(), self.decryption_key)
                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]"))
                    #print(f"Decrypted message: {decrypted}")
                    # Write data into file
                    self.log_data(decrypted)
        
            elif self.type_of_encryption == "8": # Playfair cipher full
                if message.startswith("PFCAKey:"):
                    # Format: "key: <encryption key>"
                    self.decryption_key = message[8:].strip()
                    self.message_queue.put(f"[Received Playfair cipher key: {self.decryption_key}]")
                elif message.startswith("data:"):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        self.message_queue.put(f"[ERROR] Invalid message format: {message}")
                        return
                    #self.decryption_key = self.crypto.dh_key_to_string(self.decryption_key, 6)  # Ensure key is in string format
                    encrypted_data = parts[2].strip()
                    print(f"Encrypted data: {encrypted_data}")

                    # Decrypt the message using Playfair cipher
                    decrypted = self.crypto.decrypt_playfair_full(str(b64decode(encrypted_data).decode('utf-8')).strip(), self.decryption_key)

                    if (parts[1] == Topic1):
                        self.message_queue.put((1, f"[Decrypted message: {decrypted}]")) # Show message for decrypted message
                    else:
                        self.message_queue.put((2, f"[Decrypted message: {decrypted}]"))

                    #print(f"Decrypted message: {decrypted}")
                    # Write data into file
                    self.log_data(decrypted)
        
            else: # Unknown encryption type
                self.message_queue.put(f"[Unknown Encryption Type] {self.type_of_encryption}")
                return
        
        except Exception as e: # Processing Error
            self.message_queue.put(f"[Processing Error] {str(e)}")

    def _on_error(self, ws, error): # Handle errors
        self.message_queue.put(f"[WebSocket Error] {error}")
        self.status_callback(f"Error: {error}", "#c0392b")

    def _on_close(self, ws, close_status_code, close_msg): # Handle connection close
        self.is_connected = False
        self.message_queue.put(f"[Connection Closed] Code: {close_status_code}, Message: {close_msg}")
        self.status_callback("Disconnected", "#7f8c8d")

    def _on_open(self, ws): # Handle connection open
        self.is_connected = True
        self.message_queue.put("[Connected to WebSocket Server]")

        encryption = self.cipher_var.get()
        mapping = {"AES" : 2, "Vigenère Cipher" : 3, "Playfair Cipher" : 5, "Transposition Cipher" : 4, "Ceasar Cipher" : 1,
                   "Vigenère Cipher Full": 6, "Playfair Cipher Full": 8, "Transposition Cipher Full": 7}
        self.type_of_encryption = str(mapping.get(encryption, 2))  # Default to AES if not found
        print(self.type_of_encryption)
        self.ws.send(f"type: {self.type_of_encryption}")

        self.status_callback("Connected", "#27ae60")

