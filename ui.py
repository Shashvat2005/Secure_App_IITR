from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox
import queue
import threading
from websocket_client import WebSocketClient
from graph import MessageGraph

cipher_var = None

class SecureChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Receiver")
        self.master.geometry("1200x800")
        self.master.configure(bg="#f0f2f5")
        self.master.minsize(1000, 700)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configure_styles()
        
        # Create frames
        self._create_header()
        self._create_connection_frame()
        self._create_control_buttons()
        self._create_main_content()
        self._create_status_bar()
        
        # WebSocket client
        self.ws_client = None
        self.message_queue = queue.Queue()
        self.master.after(100, self.process_queue)
        
        # Message graphs
        self.topic1_graph = MessageGraph(self.topic1_graph_frame)
        self.topic2_graph = MessageGraph(self.topic2_graph_frame)

    def _configure_styles(self):
        self.style.configure("Header.TLabel", 
                            background="#4a6fa5", 
                            foreground="white", 
                            font=("Segoe UI", 14, "bold"),
                            padding=10)
        
        self.style.configure("Status.TLabel", 
                            background="#e0e0e0", 
                            foreground="#333333",
                            font=("Segoe UI", 10),
                            padding=5)
        
        self.style.configure("TButton", 
                            font=("Segoe UI", 10),
                            padding=6)
        
        self.style.map("Connect.TButton", 
                      background=[("active", "#27ae60"), ("disabled", "#aed6c4")],
                      foreground=[("active", "white"), ("disabled", "#888888")])
        
        self.style.map("Disconnect.TButton", 
                      background=[("active", "#e74c3c"), ("disabled", "#f5b7b1")],
                      foreground=[("active", "white"), ("disabled", "#888888")])
        
        self.style.configure("MessageFrame.TLabelframe", 
                            font=("Segoe UI", 10, "bold"),
                            borderwidth=2,
                            relief="groove")
        
        self.style.configure("KeyInfo.TLabel", 
                            font=("Consolas", 9),
                            background="#f8f9fa",
                            padding=5,
                            relief="sunken")
        
        self.style.configure("GraphFrame.TFrame", 
                            background="white", 
                            borderwidth=1, 
                            relief="sunken")
        
        self.style.configure("TopicTab.TFrame", background="#ffffff", padding=5)
        self.style.configure("TopicLabel.TLabel", font=("Segoe UI", 10, "bold"))

    def _create_header(self):
        header_frame = ttk.Frame(self.master)
        header_frame.pack(fill="x", pady=(0, 10))
        
        self.title_label = ttk.Label(header_frame, 
                                   text="🔒 Secure Message Receiver", 
                                   style="Header.TLabel")
        self.title_label.pack(fill="x", padx=10, pady=5)

    def _create_connection_frame(self):
        conn_frame = ttk.LabelFrame(self.master, text="Connection Settings", padding=15)
        conn_frame.pack(fill="x", padx=10, pady=5)
        
        # Server address
        ttk.Label(conn_frame, text="WebSocket Server:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.server_entry = ttk.Entry(conn_frame, width=40, font=("Segoe UI", 10))
        self.server_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.server_entry.insert(0, "ws://192.168.0.2:8887")
        
        # Topic subscriptions
        ttk.Label(conn_frame, text="Topic 1:").grid(row=0, column=2, sticky="w", padx=(20, 5), pady=5)
        self.topic1_entry = ttk.Entry(conn_frame, width=20, font=("Segoe UI", 10))
        self.topic1_entry.grid(row=0, column=3, sticky="ew", padx=5, pady=5)
        self.topic1_entry.insert(0, 'hi')

        # Subscribe button for topic 1
        ttk.Button(conn_frame, text="Subscribe",
                   command=lambda: self.ws_client.subscribe(self.topic1_entry.get().strip(), 1),
                   style="TButton").grid(row=1, column=3, sticky="ew", padx=(5, 10), pady=5)
        

        # Topic 2 subscription
        ttk.Label(conn_frame, text="Topic 2:").grid(row=0, column=4, sticky="w", padx=(20, 5), pady=5)
        self.topic2_entry = ttk.Entry(conn_frame, width=20, font=("Segoe UI", 10))
        self.topic2_entry.grid(row=0, column=5, sticky="ew", padx=5, pady=5)
        self.topic2_entry.insert(0, 'test')

        # Subscribe button for topic 2
        ttk.Button(conn_frame, text="Subscribe",
                   command=lambda: self.ws_client.subscribe(self.topic2_entry.get().strip(), 2),
                   style="TButton").grid(row=1, column=5, sticky="ew", padx=(5, 10), pady=5)
        

        # Status indicator
        ttk.Label(conn_frame, text="Status:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.status_label = ttk.Label(conn_frame, text="Disconnected", foreground="#e74c3c")
        self.status_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        # Key information
        key_frame = ttk.Frame(conn_frame)
        key_frame.grid(row=2, column=0, columnspan=6, sticky="ew", pady=10)

        global cipher_var
        self.cipher_options = ["AES", "Vigenère Cipher", "Playfair Cipher", "Transposition Cipher", "Ceasar Cipher", "AES", "Vigenère Cipher Full", "Playfair Cipher Full", "Transposition Cipher Full"]
        cipher_var = tk.StringVar(value=self.cipher_options[0])  # Default selection

        self.cipher_label = ttk.Label(conn_frame, text="Cipher:")
        self.cipher_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.cipher_dropdown = ttk.OptionMenu(conn_frame, cipher_var, *self.cipher_options)
        self.cipher_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        #print("set:", cipher_var.get())
        
        ttk.Label(key_frame, text="Shared Key:").pack(side="left", padx=(0, 5))
        self.shared_key_label = ttk.Label(key_frame, text="Not established", style="KeyInfo.TLabel")
        self.shared_key_label.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ttk.Label(key_frame, text="AES IV:").pack(side="left", padx=(0, 5))
        self.aes_iv_label = ttk.Label(key_frame, text="Not established", style="KeyInfo.TLabel")
        self.aes_iv_label.pack(side="left", fill="x", expand=True)

    def _create_control_buttons(self):
        btn_frame = ttk.Frame(self.master)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        self.connect_btn = ttk.Button(btn_frame, 
                                    text="Connect", 
                                    command=self.connect_websocket,
                                    style="Connect.TButton")
        self.connect_btn.pack(side="left", padx=5)
        
        self.disconnect_btn = ttk.Button(btn_frame, 
                                       text="Disconnect", 
                                       command=self.disconnect_websocket,
                                       state=tk.DISABLED,
                                       style="Disconnect.TButton")
        self.disconnect_btn.pack(side="left", padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, 
                                  text="Clear Messages", 
                                  command=self.clear_messages)
        self.clear_btn.pack(side="right", padx=5)
        
        self.copy_btn = ttk.Button(btn_frame, 
                                  text="Copy All", 
                                  command=self.copy_all)
        self.copy_btn.pack(side="right", padx=5)

    def _create_main_content(self):
        """Create main content area with dual topic displays"""
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create notebook for topic tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Topic 1 tab
        topic1_frame = ttk.Frame(self.notebook, style="TopicTab.TFrame")
        self.notebook.add(topic1_frame, text="Topic 1")
        self._create_topic_content(topic1_frame, 1)
        
        # Topic 2 tab
        topic2_frame = ttk.Frame(self.notebook, style="TopicTab.TFrame")
        self.notebook.add(topic2_frame, text="Topic 2")
        self._create_topic_content(topic2_frame, 2)

    def _create_topic_content(self, parent_frame, topic_num):
        """Create content for a single topic tab"""
        # Topic label
        topic_label = ttk.Label(parent_frame, 
                              text=f"Topic {topic_num} Messages", 
                              style="TopicLabel.TLabel")
        topic_label.pack(fill="x", padx=10, pady=5)
        
        # Create paned window for resizable split
        paned_window = ttk.PanedWindow(parent_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Message frame (left side)
        msg_frame = ttk.LabelFrame(paned_window, 
                                 text="Messages", 
                                 style="MessageFrame.TLabelframe", 
                                 padding=10)
        paned_window.add(msg_frame, weight=2)  # 60% width
        
        # Create text area for this topic
        text_area = tk.Text(msg_frame, 
                           wrap='word', 
                           font=("Consolas", 10),
                           bg="white", 
                           fg="#333333",
                           padx=10,
                           pady=10,
                           relief="flat",
                           highlightbackground="#cccccc",
                           highlightthickness=1)
        text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(msg_frame, command=text_area.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_area.config(yscrollcommand=scrollbar.set)
        text_area.config(state=tk.DISABLED)
        
        # Store reference to text area
        if topic_num == 1:
            self.topic1_text_area = text_area
        else:
            self.topic2_text_area = text_area
        
        # Graph frame (right side)
        graph_frame = ttk.LabelFrame(paned_window, 
                                   text="Message Values", 
                                   style="MessageFrame.TLabelframe", 
                                   padding=10)
        paned_window.add(graph_frame, weight=1)  # 40% width
        
        # Store reference to graph frame
        if topic_num == 1:
            self.topic1_graph_frame = graph_frame
        else:
            self.topic2_graph_frame = graph_frame
    
    def _create_message_area(self):
        msg_frame = ttk.LabelFrame(self.master, text="Received Messages", style="MessageFrame.TLabelframe", padding=10)
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.text_area = tk.Text(msg_frame, 
                                wrap='word', 
                                font=("Consolas", 10),
                                bg="white", 
                                fg="#333333",
                                padx=10,
                                pady=10,
                                relief="flat",
                                highlightbackground="#cccccc",
                                highlightthickness=1)
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(msg_frame, command=self.text_area.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.config(yscrollcommand=scrollbar.set)
        self.text_area.config(state=tk.DISABLED)

    def _create_status_bar(self):
        self.status_bar = ttk.Label(self.master, 
                                  text="Ready", 
                                  style="Status.TLabel",
                                  anchor="center")
        self.status_bar.pack(fill="x", side="bottom", ipady=5)

    def update_status(self, message, color="#333333"):
        self.status_label.config(text=message, foreground=color)
        self.status_bar.config(text=f"Status: {message}")

    def update_key_info(self, shared_key, aes_iv):
        self.shared_key_label.config(text=shared_key[:24] + "..." if shared_key else "Not established")
        self.aes_iv_label.config(text=aes_iv[:24] + "..." if aes_iv else "Not established")

    def display_message(self, topic, message):
        """Display message in the appropriate topic tab"""
        if topic == 1:
            text_area = self.topic1_text_area
            graph = self.topic1_graph
        else:
            text_area = self.topic2_text_area
            graph = self.topic2_graph
            
        text_area.config(state=tk.NORMAL)
        text_area.insert(tk.END, message + '\n')
        text_area.see(tk.END)
        text_area.config(state=tk.DISABLED)
        
        # Try to parse numeric value for graphing
        try:
            # Extract the numeric part after the colon
            value_part = message.split(":", 1)[1].strip() if ":" in message else message

            #print(f"Value part extracted for graphing: {value_part}")  # Debug for graph not working
            #print(f"Type of value_part: {type(value_part)}")  # Debug for graph not working
        
            numeric_value = float(value_part)
            graph.add_data_point(numeric_value)
        except (ValueError, IndexError) as e:
            # Not a numeric value, skip graphing
            #print(f"Skipping graphing for non-numeric message: {message}, Error:({e})") # Debug for graph not working
            pass

    def clear_messages(self):
        """Clear all messages and graphs"""
        # Clear topic 1
        self.topic1_text_area.config(state=tk.NORMAL)
        self.topic1_text_area.delete(1.0, tk.END)
        self.topic1_text_area.config(state=tk.DISABLED)
        self.topic1_graph.reset()
        
        # Clear topic 2
        self.topic2_text_area.config(state=tk.NORMAL)
        self.topic2_text_area.delete(1.0, tk.END)
        self.topic2_text_area.config(state=tk.DISABLED)
        self.topic2_graph.reset()
        
        self.status_bar.config(text="All messages cleared")

    def copy_all(self):
        """Copy all messages from both topics to clipboard"""
        all_messages = ""
        
        # Get topic 1 messages
        self.topic1_text_area.config(state=tk.NORMAL)
        all_messages += "=== Topic 1 ===\n"
        all_messages += self.topic1_text_area.get(1.0, tk.END)
        self.topic1_text_area.config(state=tk.DISABLED)
        
        # Get topic 2 messages
        self.topic2_text_area.config(state=tk.NORMAL)
        all_messages += "\n=== Topic 2 ===\n"
        all_messages += self.topic2_text_area.get(1.0, tk.END)
        self.topic2_text_area.config(state=tk.DISABLED)
        
        self.master.clipboard_clear()
        self.master.clipboard_append(all_messages)
        self.status_bar.config(text="All messages copied to clipboard")

    def process_queue(self):
        while not self.message_queue.empty():
            message = self.message_queue.get()
            if isinstance(message, tuple) and len(message) == 2:
                topic, content = message
                self.display_message(topic, content)
            else:
                # Display in both tabs for system messages
                self.display_message(1, message)
                self.display_message(2, message)
        self.master.after(100, self.process_queue)

    def connect_websocket(self):
        if self.ws_client and self.ws_client.is_connected:
            return

        server_url = self.server_entry.get().strip()
        
        if not server_url:
            messagebox.showerror("Error", "Please enter a valid WebSocket URL")
            return
        
        global cipher_var
        #print(cipher_var)
        self.update_status("Connecting...", "#f39c12")
        self.ws_client = WebSocketClient(
            url=server_url,
            message_queue=self.message_queue,
            status_callback=self.update_status,
            key_callback=self.update_key_info,
            cipher_var=cipher_var
        )
        
        self.ws_thread = threading.Thread(target=self.ws_client.run)
        self.ws_thread.daemon = True
        self.ws_thread.start()
        
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)

    def disconnect_websocket(self):
        if self.ws_client and self.ws_client.is_connected:
            self.ws_client.close()
            self.update_status("Disconnected", "#e74c3c")
            self.message_queue.put("[WebSocket Connection Closed]")
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)



word = "dabdcbdcdcd"
k = 2

d,g = {},{}

for i in word:
    if i in d:
        d[i] += 1
    else:
        d[i] = 1

rem = 0
c = sorted(d)
for i in c:
    g[i] = d[i]

for j in g:
    pass