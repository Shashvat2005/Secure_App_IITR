import tkinter as tk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from collections import deque
import threading

class MessageGraph:
    def __init__(self, parent_frame, max_points=100, update_interval=500):
        self.parent = parent_frame
        self.max_points = max_points
        self.update_interval = update_interval
        self.data_points = deque(maxlen=max_points)
        self.timestamps = deque(maxlen=max_points)
        self.last_update = time.time()
        
        # Create figure and axes
        self.fig = Figure(figsize=(5, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title('Message Values')
        self.ax.set_xlabel('Time (s)')
        self.ax.set_ylabel('Value')
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.line, = self.ax.plot([], [], 'b-', marker='o', markersize=4)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Start update thread
        self.running = True
        self.update_thread = threading.Thread(target=self.update_graph)
        self.update_thread.daemon = True
        self.update_thread.start()
    
    def add_data_point(self, value):
        """Add a new data point with current timestamp"""
        current_time = time.time()
        self.timestamps.append(current_time)
        self.data_points.append(value)
    
    def update_graph(self):
        """Continuously update the graph"""
        while self.running:
            if self.timestamps:
                # Convert timestamps to relative time
                relative_times = [t - self.timestamps[0] for t in self.timestamps]
                
                # Update plot data
                self.line.set_data(relative_times, self.data_points)
                
                # Adjust axes
                self.ax.relim()
                self.ax.autoscale_view()
                
                # Redraw canvas
                self.canvas.draw()
            
            time.sleep(self.update_interval / 1000)
    
    def reset(self):
        """Reset graph data"""
        self.data_points.clear()
        self.timestamps.clear()
        self.line.set_data([], [])
        self.canvas.draw()
    
    def close(self):
        """Stop update thread"""
        self.running = False
        if self.update_thread.is_alive():
            self.update_thread.join(timeout=1.0)