import tkinter as tk
from tkinter import ttk, messagebox
import queue
import threading
from websocket_client import WebSocketClient
from graph import MessageGraph

class SecureChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Receiver")
        self.master.geometry("1000x700")
        self.master.configure(bg="#f0f2f5")
        self.master.minsize(800, 600)
        
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
        
        # Message graph
        self.message_graph = MessageGraph(self.graph_frame)

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
        self.server_entry.insert(0, "ws://10.170.91.131:8887")
        
        # Topic subscription
        ttk.Label(conn_frame, text="Subscribe Topic:").grid(row=0, column=2, sticky="w", padx=(20, 5), pady=5)
        self.topic_entry = ttk.Entry(conn_frame, width=20, font=("Segoe UI", 10))
        self.topic_entry.grid(row=0, column=3, sticky="ew", padx=5, pady=5)
        self.topic_entry.insert(0, "test/topic")
        
        # Status indicator
        ttk.Label(conn_frame, text="Status:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.status_label = ttk.Label(conn_frame, text="Disconnected", foreground="#e74c3c")
        self.status_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        # Key information
        key_frame = ttk.Frame(conn_frame)
        key_frame.grid(row=2, column=0, columnspan=4, sticky="ew", pady=10)
        
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
        """Create main content area with message display and graph"""
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create paned window for resizable split
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Message frame (left side)
        msg_frame = ttk.LabelFrame(paned_window, text="Received Messages", style="MessageFrame.TLabelframe", padding=10)
        paned_window.add(msg_frame, weight=3)  # 60% width
        
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
        
        # Graph frame (right side)
        self.graph_frame = ttk.LabelFrame(paned_window, text="Message Frequency", style="MessageFrame.TLabelframe", padding=10)
        paned_window.add(self.graph_frame, weight=2)  # 40% width

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

    def display_message(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.see(tk.END)
        self.text_area.config(state=tk.DISABLED)
        
        # Update graph with new message
        if "Decrypted" in message or "Raw Message" in message:
            self.message_graph.add_data_point()

    def clear_messages(self):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        self.status_bar.config(text="Messages cleared")

    def copy_all(self):
        self.master.clipboard_clear()
        self.master.clipboard_append(self.text_area.get(1.0, tk.END))
        self.status_bar.config(text="Messages copied to clipboard")

    def process_queue(self):
        while not self.message_queue.empty():
            message = self.message_queue.get()
            self.display_message(message)
        self.master.after(100, self.process_queue)

    def connect_websocket(self):
        if self.ws_client and self.ws_client.is_connected:
            return

        server_url = self.server_entry.get().strip()
        if not server_url:
            messagebox.showerror("Error", "Please enter a valid WebSocket URL")
            return

        self.update_status("Connecting...", "#f39c12")
        self.ws_client = WebSocketClient(
            url=server_url,
            message_queue=self.message_queue,
            status_callback=self.update_status,
            key_callback=self.update_key_info,
            topic=self.topic_entry.get().strip()
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