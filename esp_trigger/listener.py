import time
import serial
import serial.tools.list_ports
import sys
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
except ImportError:
    print("Please install customtkinter: pip install customtkinter")
    sys.exit(1)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".pdf", ".lock", ".sum", ".exe", ".dll", ".so", ".bin"
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".idea", ".vscode"}

class ScannerGUI(ctk.CTk):
    def __init__(self, serial_port):
        super().__init__()
        self.ser = serial_port
        self.title("Nuclear Secret Scanner")
        self.geometry("750x600")
        self.resizable(True, True)
        self.eval('tk::PlaceWindow . center')
        self.attributes('-topmost', True)

        self.label = ctk.CTkLabel(self, text="☢️ ESP32 Hardware Scan Engine", font=ctk.CTkFont(size=26, weight="bold"), text_color="#ff4757")
        self.label.pack(pady=(20, 5))

        self.sub_label = ctk.CTkLabel(self, text="True Hardware Verification Connected. Select directory to scream data to ESP.", font=ctk.CTkFont(size=14))
        self.sub_label.pack(pady=(0, 20))

        self.output_box = ctk.CTkTextbox(self, width=700, height=300, font=ctk.CTkFont(family="Consolas", size=12))
        self.output_box.pack(pady=10, padx=20, fill="both", expand=True)
        self.output_box.insert("0.0", "Awaiting scan...\n")
        self.output_box.configure(state="disabled")

        self.stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_frame.pack(pady=5)
        
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.stat_labels = {}
        colors = {"CRITICAL": "#ff4757", "HIGH": "#ff7f50", "MEDIUM": "#ffa502", "LOW": "#1e90ff"}
        
        for sev, color in colors.items():
            lbl = ctk.CTkLabel(self.stats_frame, text=f"{sev}: 0", font=ctk.CTkFont(size=13, weight="bold"), text_color=color, width=90)
            lbl.pack(side="left", padx=5)
            self.stat_labels[sev] = lbl

        self.scan_btn = ctk.CTkButton(self, text="Select Directory & Scan", command=self.select_directory, font=ctk.CTkFont(size=14, weight="bold"), height=40, width=200, fg_color="#2f3542", hover_color="#57606f")
        self.scan_btn.pack(pady=10)
        
        self.status_label = ctk.CTkLabel(self, text="Waiting for input...", font=ctk.CTkFont(size=12, slant="italic"), text_color="gray")
        self.status_label.pack(pady=(5, 10))
        
        # We need a dedicated frame for the big red authorization button
        self.auth_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.auth_frame.pack(pady=5)
        self.auth_label = ctk.CTkLabel(self.auth_frame, text="", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ff4757")
        self.auth_label.pack()
        
        self.findings = []
        self.export_thread = None

    def log_output(self, text):
        self.output_box.configure(state="normal")
        self.output_box.insert("end", text)
        self.output_box.see("end")
        self.output_box.configure(state="disabled")

    def increment_stat(self, severity):
        if severity in self.counts:
            self.counts[severity] += 1
            self.stat_labels[severity].configure(text=f"{severity}: {self.counts[severity]}")

    def select_directory(self):
        # Reset state
        for sev in self.counts.keys():
            self.counts[sev] = 0
            self.stat_labels[sev].configure(text=f"{sev}: 0")
        self.findings.clear()
        self.auth_label.configure(text="")
            
        self.attributes('-topmost', False)
        directory = filedialog.askdirectory(title="Select Directory to Stream to ESP")
        self.attributes('-topmost', True)
        
        if directory:
            self.status_label.configure(text=f"Streaming: {os.path.basename(directory)}", text_color="#1e90ff")
            self.update()
            self.run_hardware_scan(directory)

    def run_hardware_scan(self, directory):
        self.scan_btn.configure(state="disabled")
        self.output_box.configure(state="normal")
        self.output_box.delete("0.0", "end")
        self.output_box.configure(state="disabled")
        self.log_output(f"Starting hardware streaming scan for: {directory}\n======================================================\n")

        def streamer_task():
            try:
                self.ser.write(b"CMD:SCAN_START\n")
                
                # Recursively walk and stream lines
                files_scanned = 0
                for root, dirs, files in os.walk(directory):
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in SKIP_EXTENSIONS:
                            continue
                            
                        filepath = os.path.join(root, file)
                        try:
                            # Read as text and stream
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    # Very naive stripping to prevent blowing up the ESP buffer
                                    content = line.strip()
                                    if content:
                                        try:
                                            # Send to ESP32 Core 1!
                                            self.ser.write((content + "\n").encode('utf-8'))
                                            # Yield a tiny bit to not overflow the CH340 buffer
                                            time.sleep(0.005)
                                        except Exception as e:
                                            # Catch permission errors if COM port buffer fills up on Windows
                                            time.sleep(0.1)
                                            continue
                            files_scanned += 1
                        except Exception:
                            pass
                            
                try:
                    self.ser.write(b"CMD:SCAN_END\n")
                except:
                    pass
                self.after(0, lambda: self.log_output(f"\n[INFO] Complete. Streamed {files_scanned} files to ESP32.\n"))
                self.after(2000, self.force_unlock_ui)
                
            except Exception as e:
                self.after(0, lambda: self.log_output(f"\n[ERROR] Streaming failed: {e}\n"))
                self.after(0, lambda: self.scan_btn.configure(state="normal"))

        # Start background reader for ESP32 responses
        def reader_task():
            while True:
                try:
                    if self.ser.in_waiting > 0:
                        line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                        if line.startswith("FINDING:"):
                            parts = line.split(":", 3)
                            if len(parts) >= 4:
                                sev = parts[1]
                                pattern = parts[2]
                                content = parts[3]
                                self.after(0, self.increment_stat, sev)
                                self.after(0, self.log_output, f"[{sev}] {pattern} -> {content}\n")
                                self.findings.append((pattern, content))
                        elif line.startswith("SYS:AUTHORIZE_EXPORT"):
                            self.after(0, lambda: self.auth_label.configure(text="🚨 Secrets Found! Automatically exported to Desktop.", text_color="#2ed573"))
                            self.export_secrets()
                            self.after(0, lambda: self.scan_btn.configure(state="normal"))
                            self.after(0, lambda: self.status_label.configure(text="Waiting for input..."))
                            break # End reader for this run
                        elif line == "SYS:SCAN_CLEAN":
                            self.after(0, lambda: self.auth_label.configure(text="✅ Scan Complete. No hardware secrets found.", text_color="#2ed573"))
                            self.after(0, lambda: self.scan_btn.configure(state="normal"))
                            self.after(0, lambda: self.status_label.configure(text="Waiting for input..."))
                            break # End reader for this run
                except Exception:
                    time.sleep(0.1)
                    
        # Start the threads
        threading.Thread(target=streamer_task, daemon=True).start()
        threading.Thread(target=reader_task, daemon=True).start()
        
    def force_unlock_ui(self):
        if self.scan_btn.cget("state") == "disabled":
            self.scan_btn.configure(state="normal")
            self.status_label.configure(text="Waiting for input... (Forced Unlock)")
            if not self.auth_label.cget("text"):
                self.auth_label.configure(text="✅ Scan Complete. (Hardware response timeout)", text_color="gray")
                
    def export_secrets(self):
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        env_path = os.path.join(desktop, "leaked_secrets.env")
        try:
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write(f"# Exported by Nuclear Scanner ESP32 Token\n")
                f.write(f"# Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for idx, (pattern, content) in enumerate(self.findings):
                    f.write(f"FOUND_{pattern.replace(' ', '_').upper()}_{idx}=\"{content}\"\n")
            
            self.after(0, lambda: self.log_output(f"\n[SUCCESS] Secrets physically authorized & saved to {env_path}\n"))
        except Exception as e:
            self.after(0, lambda: self.log_output(f"\n[ERROR] Failed to save secrets: {e}\n"))

def listen_for_token():
    print(f"Nuclear Listener started. Waiting for ESP32-CAM (v2 Hardware Scanner) on COM ports...")
    checked_ports = set()
    
    while True:
        try:
            current_ports = {p.device for p in serial.tools.list_ports.comports()}
            
            for port in current_ports:
                if port not in checked_ports:
                    try:
                        ser = serial.Serial(port, 115200, timeout=1.5)
                        line = ser.readline().decode('utf-8', errors='ignore').strip()
                        if "NUCLEAR_SCANNER_READY" in line:
                            print(f"Token detected securely on {port}!")
                            app = ScannerGUI(ser)
                            app.mainloop()
                            # GUI closed, drop connection
                            ser.close()
                            checked_ports.add(port)
                        else:
                            ser.close()
                            checked_ports.add(port)
                    except serial.SerialException:
                        checked_ports.add(port)
            
            checked_ports.intersection_update(current_ports)
            time.sleep(1)
            
        except Exception as e:
            time.sleep(5)

if __name__ == "__main__":
    listen_for_token()
