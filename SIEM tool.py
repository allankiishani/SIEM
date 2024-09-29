import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from threading import Thread, Event
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import textwrap
import psutil
import time
import win32evtlog
import pyuac

class NetworkAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("System Analytics Dashboard")
        self.geometry("800x600")

        self.setup_widgets()

    def setup_widgets(self):
        # Create a notebook (tabbed layout)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create the Network Analyzer tab
        self.network_analyzer_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.network_analyzer_tab, text="Network Analyzer")
        self.setup_network_analyzer_tab()

        # Create the Log Collector tab
        self.log_collector_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_collector_tab, text="Log Collector")
        self.setup_log_collector_tab()

        # Create the System Analytics tab
        self.system_analytics_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.system_analytics_tab, text="System Analytics")
        self.setup_system_analytics_tab()

    def setup_network_analyzer_tab(self):
        # Start Capture Button
        self.start_btn = tk.Button(self.network_analyzer_tab, text="Start Capture", command=self.start_capture, font=("Arial", 12))
        self.start_btn.pack()

        # Stop Capture Button
        self.stop_btn = tk.Button(self.network_analyzer_tab, text="Stop Capture", command=self.stop_capture, font=("Arial", 12), state=tk.DISABLED)
        self.stop_btn.pack()

        # Treeview to display packet information
        self.packet_tree = ttk.Treeview(self.network_analyzer_tab)
        self.packet_tree["columns"] = ("Time", "Source IP", "Destination IP", "Protocol", "Length")
        self.packet_tree.heading("#0", text="Index")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source IP", text="Source IP")
        self.packet_tree.heading("Destination IP", text="Destination IP")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Length", text="Length")
        self.packet_tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Graph display area
        self.graph_frame = tk.Frame(self.network_analyzer_tab)
        self.graph_frame.pack(pady=10, fill=tk.BOTH, expand=True)

    def start_capture(self):
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.packet_tree.delete(*self.packet_tree.get_children())  # Clear existing data
        self.capture_thread = Thread(target=self.packet_capture_thread)
        self.capture_thread.start()

    def stop_capture(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.capture_thread.join()

    def packet_capture_thread(self):
        sniff(prn=self.handle_packet)

    def handle_packet(self, packet):
        capture_time = packet.time
        formatted_time = datetime.fromtimestamp(capture_time).strftime('%Y-%m-%d %H:%M:%S.%f')
        source_ip = packet[IP].src if IP in packet else ""
        dest_ip = packet[IP].dst if IP in packet else ""
        protocol = packet[IP].proto if IP in packet else ""
        length = len(packet)

        self.packet_tree.insert("", "end", values=(formatted_time, source_ip, dest_ip, protocol, length))

    def setup_log_collector_tab(self):
        self.log_treeview = ttk.Treeview(self.log_collector_tab, columns=["TimeGenerated", "SourceName", "EventID", "StringInserts"], show="headings")
        self.log_treeview.heading("TimeGenerated", text="Time Generated")
        self.log_treeview.heading("SourceName", text="Source Name")
        self.log_treeview.heading("EventID", text="Event ID")
        self.log_treeview.heading("StringInserts", text="String Inserts")
        self.log_treeview.pack(fill="both", expand=True)

        self.log_monitor = LogFileMonitor(self.log_treeview)
        self.log_monitor.start()

    def setup_system_analytics_tab(self):
        self.system_analytics_frame = tk.Frame(self.system_analytics_tab, bg="light blue")
        self.system_analytics_frame.pack(fill=tk.BOTH, expand=True)

        self.login_logout_label = tk.Label(self.system_analytics_frame, text="Login/Logout Times", font=("Arial", 12), bg="light blue")
        self.login_logout_label.pack()

        self.login_logout_text = scrolledtext.ScrolledText(self.system_analytics_frame, wrap=tk.WORD, width=40, height=10)
        self.login_logout_text.pack()

        self.file_access_label = tk.Label(self.system_analytics_frame, text="File Access Privileges", font=("Arial", 12), bg="light blue")
        self.file_access_label.pack()

        self.file_access_text = scrolledtext.ScrolledText(self.system_analytics_frame, wrap=tk.WORD, width=40, height=10)
        self.file_access_text.pack()

        self.update_button = tk.Button(self.system_analytics_frame, text="Update Dashboard", command=self.update_dashboard, font=("Arial", 12))
        self.update_button.pack()

        # Update the dashboard initially
        self.update_dashboard()

    def update_dashboard(self):
        login_logout_data = get_login_logout_times()
        file_access_data = get_file_access_privileges()

        self.display_login_logout_times(login_logout_data)
        self.display_file_access_privileges(file_access_data)

    def display_login_logout_times(self, data):
        self.login_logout_text.delete('1.0', tk.END)
        for row in data:
            self.login_logout_text.insert(tk.END, f"Timestamp: {row['Timestamp']}\tEvent: {row['Event']}\n")

    def display_file_access_privileges(self, data):
        self.file_access_text.delete('1.0', tk.END)
        for row in data:
            self.file_access_text.insert(tk.END, f"File: {row['File']}\tPrivilege: {row['Privilege']}\n")

class LogFileMonitor(threading.Thread):
    def __init__(self, treeview):
        super().__init__()
        self.treeview = treeview
        self.running = True

    def run(self):
        while self.running:
            time.sleep(1)
            logs = self.fetch_system_logs()
            if logs:
                self.treeview.delete(*self.treeview.get_children())
                for log in logs:
                    self.treeview.insert("", "end", values=(log['TimeGenerated'], log['SourceName'], log['EventID'], log['StringInserts']))

    def stop(self):
        self.running = False

    def fetch_system_logs(self):
        try:
            logs = []
            hand = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            for event in events:
                logs.append({
                    'TimeGenerated': event.TimeGenerated.Format(),
                    'SourceName': event.SourceName,
                    'EventID': event.EventID,
                    'StringInserts': event.StringInserts
                })
            win32evtlog.CloseEventLog(hand)
            return logs
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch system logs: {e}")
            return []

def get_login_logout_times():
    boot_time = psutil.boot_time()
    current_time = time.time()
    uptime = current_time - boot_time
    return [{'Timestamp': boot_time, 'Event': 'Login'}, {'Timestamp': uptime, 'Event': 'Uptime'}]

def get_file_access_privileges():
    processes = [proc.info for proc in psutil.process_iter(['pid', 'name', 'username'])]
    return [{'File': proc['name'], 'Privilege': proc['username']} for proc in processes]

if __name__ == "__main__":
    if not pyuac.isUserAdmin():
        pyuac.runAsAdmin()
    else:
        NetworkAnalyzerApp().mainloop()
