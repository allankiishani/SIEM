import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from threading import Thread
from scapy.arch.windows import get_windows_if_list
import scapy.all as scapy

class NetworkAnalyzer:
    def __init__(self, gui):
        self.gui = gui
        self.running = False
        self.interface = None

    def start_capture(self):
        self.running = True
        try:
            while self.running:
                if self.interface:
                    packet = scapy.sniff(iface=self.interface, count=1)
                    self.process_packet(packet[0])
                else:
                    print("No network interface selected.")
                    break
        except Exception as e:
            print(f"Error capturing packets: {e}")

    def process_packet(self, packet):
        packet_info = f"Source: {packet.src}, Destination: {packet.dst}, Protocol: {packet.name}"
        self.gui.display_packet(packet_info)

    def stop_capture(self):
        self.running = False

class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Traffic Analyzer")

        self.start_button = ttk.Button(self.root, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = ttk.Button(self.root, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(row=0, column=1, padx=10, pady=10)

        self.interface_dropdown = ttk.Combobox(self.root, state="readonly")
        self.interface_dropdown.grid(row=0, column=2, padx=10, pady=10)

        self.packet_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.packet_display.grid(row=1, columnspan=3, padx=10, pady=10)

        self.analyzer = NetworkAnalyzer(self)

    def start_capture(self):
        selected_interface = self.interface_dropdown.get()
        if selected_interface:
            self.analyzer.interface = selected_interface
            self.start_button['state'] = 'disabled'
            self.stop_button['state'] = 'normal'
            capture_thread = Thread(target=self.analyzer.start_capture)
            capture_thread.start()
        else:
            print("Please select a network interface.")

    def stop_capture(self):
        self.analyzer.stop_capture()
        self.start_button['state'] = 'normal'
        self.stop_button['state'] = 'disabled'

    def display_packet(self, packet_info):
        self.packet_display.insert(tk.END, packet_info + "\n")
        self.packet_display.see(tk.END)

    def update_interface_list(self):
        interface_list = [interface["name"] for interface in get_windows_if_list()]
        self.interface_dropdown['values'] = interface_list

    def run(self):
        self.update_interface_list()
        self.root.mainloop()

if __name__ == "__main__":
    gui = GUI()
    gui.run()
