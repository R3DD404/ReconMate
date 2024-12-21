import customtkinter as ctk
import threading
import requests
import socket
from queue import Queue
from datetime import datetime
from urllib.parse import urlparse

class ReconMate(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ReconMate")
        self.geometry("800x600")
        self.scanning = False
        self.stop_event = threading.Event()

        ctk.set_appearance_mode("dark")  # Assuming dark mode for a cleaner look
        ctk.set_default_color_theme("blue")  # Default theme, can be changed

        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.pack(side="left", fill="y")

        # Home Section
        self.home_section()
        
        # Port Scanning Section
        self.port_scan_section()
        
        # Subdir Section
        self.subdir_section()

        # Clear Result Button
        self.clear_button = ctk.CTkButton(self.sidebar_frame, text="Clear Results", command=self.clear_results, font=("Arial", 14))
        self.clear_button.pack(pady=10)

        # Main frame
        self.main_frame = ctk.CTkFrame(self, width=600, height=600)
        self.main_frame.pack(side="right", fill="both", expand=True)

        self.welcome_label = ctk.CTkLabel(self.main_frame, text="Welcome to ReconMate!", font=("Arial", 20))
        self.welcome_label.pack(pady=20)

        self.target_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Enter target IP or URL", font=("Arial", 16), width=400)
        self.target_entry.pack(pady=10)

        # Options for scanning
        self.option_frame = ctk.CTkFrame(self.main_frame)
        self.option_frame.pack(pady=10)

        self.selected_option = ctk.StringVar()  # Variable to hold the selected option

        for option in ["Port Scanning", "Subdir"]:
            ctk.CTkRadioButton(self.option_frame, text=option, variable=self.selected_option, value=option, font=("Arial", 14)).pack(pady=5)

        self.start_scan_button = ctk.CTkButton(self.main_frame, text="Start Scan", command=self.toggle_scan, font=("Arial", 16))
        self.start_scan_button.pack(pady=10)

        self.progress_bar = ctk.CTkProgressBar(self.main_frame, width=400)
        self.progress_bar.pack(pady=10)

        # Results frame
        self.results_frame = ctk.CTkFrame(self.main_frame, height=200)
        self.results_frame.pack(side="bottom", fill="x")

        self.results_text = ctk.CTkTextbox(self.results_frame, width=600, height=200, font=("Arial", 14))
        self.results_text.pack()

    def home_section(self):
        home = ctk.CTkFrame(self.sidebar_frame)
        home.pack(pady=10)
        ctk.CTkLabel(home, text="Home", font=("Arial", 18)).pack(pady=5)
        ctk.CTkLabel(home, text="Created by @R3DD404", font=("Arial", 12)).pack(pady=5)
        ctk.CTkButton(home, text="Instructions", command=self.show_instructions, font=("Arial", 14)).pack(pady=5)

    def port_scan_section(self):
        port_scan = ctk.CTkFrame(self.sidebar_frame)
        port_scan.pack(pady=10)
        ctk.CTkLabel(port_scan, text="Port Scanning", font=("Arial", 18)).pack(pady=5)
        ctk.CTkButton(port_scan, text="Run Scan", command=self.start_port_scan, font=("Arial", 14)).pack(pady=5)
        self.port_scan_results = ctk.CTkLabel(port_scan, text="Last Scan: None", font=("Arial", 12))
        self.port_scan_results.pack(pady=5)

    def subdir_section(self):
        subdir = ctk.CTkFrame(self.sidebar_frame)
        subdir.pack(pady=10)
        ctk.CTkLabel(subdir, text="Subdir", font=("Arial", 18)).pack(pady=5)
        ctk.CTkButton(subdir, text="Run Scan", command=self.start_subdir_scan, font=("Arial", 14)).pack(pady=5)
        self.subdir_results = ctk.CTkLabel(subdir, text="Last Scan: None", font=("Arial", 12))
        self.subdir_results.pack(pady=5)

    def show_instructions(self):
        instructions = (
            "1. Enter the target IP or URL.\n"
            "2. Choose scan type from options.\n"
            "3. Click 'Start Scan' to begin.\n"
            "4. Use the sidebar for quick access to scans.\n"
            "5. 'Stop Scan' will halt the scan process."
        )
        ctk.CTkMessagebox(title="Instructions", message=instructions, icon="info", font=("Arial", 14))

    def clear_results(self):
        self.results_text.delete("1.0", "end")
        self.port_scan_results.configure(text="Last Scan: None")
        self.subdir_results.configure(text="Last Scan: None")

    def start_port_scan(self):
        self.selected_option.set("Port Scanning")
        self.start_scan()

    def start_subdir_scan(self):
        self.selected_option.set("Subdir")
        self.start_scan()

    def toggle_scan(self):
        if self.scanning:
            self.stop_event.set()
            self.start_scan_button.configure(text="Start Scan")
            self.scanning = False
        else:
            target = self.target_entry.get()
            selected = self.selected_option.get()

            if not target or not selected:
                self.results_text.insert("end", "Please enter a target and select an option.\n")
                return

            self.stop_event.clear()
            self.scanning = True
            self.start_scan_button.configure(text="Stop Scan")
            threading.Thread(target=self.perform_scan, args=(target, selected)).start()

    def start_scan(self):
        target = self.target_entry.get()
        selected = self.selected_option.get()

        if not target or not selected:
            self.results_text.insert("end", "Please enter a target and select an option.\n")
            return

        self.stop_event.clear()
        self.scanning = True
        self.start_scan_button.configure(text="Stop Scan")
        threading.Thread(target=self.perform_scan, args=(target, selected)).start()

    def perform_scan(self, target, option):
        self.progress_bar.set(0)
        self.clear_results()

        try:
            parsed = urlparse(target)
            if parsed.scheme:
                host = parsed.netloc
            else:
                host = target

            if option == "Port Scanning":
                self.port_scanning(host)
                self.port_scan_results.configure(text=f"Last Scan: {target}")
            elif option == "Subdir":
                self.subdir_scan(target)
                self.subdir_results.configure(text=f"Last Scan: {target}")

        except Exception as e:
            self.results_text.insert("end", f"An error occurred: {e}\n")

        self.progress_bar.set(1)
        self.results_text.insert("end", f"Scanning {target} with {option} completed!\n")
        self.scanning = False
        self.start_scan_button.configure(text="Start Scan")

    def port_scanning(self, target):
        socket.setdefaulttimeout(0.30)
        discovered_ports = []
        print_lock = threading.Lock()

        try:
            t_ip = socket.gethostbyname(target)
        except (UnboundLocalError, socket.gaierror):
            self.results_text.insert("end", "\n[-]Invalid format. Please use a correct IP or web address[-]\n")
            return

        common_ports = [21, 22, 23, 25, 53, 69, 80, 443, 110, 111, 135, 137, 139, 143, 161, 162, 389, 445, 514, 515,
                        631, 873, 990, 993, 995, 1025, 1080, 1433, 1723, 1900, 2049, 3000, 3128, 3268, 3306, 3389, 4899,
                        5000, 5060, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7000, 8000, 8008, 8009, 8080,
                        8443, 8888, 9000, 9100, 9999, 10000, 27017, 32768] + list(range(49152, 49200))

        self.results_text.insert("end", "-" * 60 + "\n")
        t1 = datetime.now()
        self.results_text.insert("end", f"Scanning target {t_ip}\n")
        self.results_text.insert("end", f"Time started: {t1}\n")
        self.results_text.insert("end", "-" * 60 + "\n")

        def portscan(port):
            if self.stop_event.is_set():
                return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((t_ip, port))
                with print_lock:
                    self.results_text.insert("end", f"Port {port} is open\n")
                    discovered_ports.append(str(port))
                s.close()
            except (ConnectionRefusedError, AttributeError, OSError):
                pass

        def threader():
            while True:
                worker = q.get()
                portscan(worker)
                q.task_done()
                if self.stop_event.is_set():
                    break

        q = Queue()

        for _ in range(100):  # Reduced to 100 threads to ease system load
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()

        for worker in common_ports:
            q.put(worker)

        q.join()

        t2 = datetime.now()
        total = t2 - t1
        self.results_text.insert("end", f"Port scan completed in {total}\n")
        self.results_text.insert("end", "-" * 60 + "\n")

        if discovered_ports:
            nmap_command = f"nmap -p{','.join(discovered_ports)} -sV -sC -T4 -Pn -oA {target} {target}"
            self.results_text.insert("end", "Port Scanning recommends the following Nmap scan:\n")
            self.results_text.insert("end", "*" * 60 + "\n")
            self.results_text.insert("end", f"{nmap_command}\n")
            self.results_text.insert("end", "*" * 60 + "\n")
        else:
            self.results_text.insert("end", "No open ports found.\n")

    def subdir_scan(self, target):
        try:
            wordlist_path = "wordlist.txt"  # Update path if needed

            with open(wordlist_path, "r") as wordlist:
                self.results_text.insert("end", f"Starting Subdir scan on {target}...\n")
                for line in wordlist:
                    if self.stop_event.is_set():
                        break
                    subdir = line.strip()
                    if not target.startswith('http'):
                        target = 'https://' + target
                    url = f"{target.rstrip('/')}/{subdir}"

                    try:
                        response = requests.get(url, timeout=5, verify=False)  # Adjust timeout and SSL verification
                        if response.status_code in [200, 401]:  # Found or unauthorized
                            self.results_text.insert("end", f"[{response.status_code}] {url}\n")
                    except requests.RequestException as e:
                        self.results_text.insert("end", f"Error accessing {url}: {e}\n")

            self.results_text.insert("end", "Subdir scan completed!\n")
        except Exception as e:
            self.results_text.insert("end", f"Error during Subdir scan: {e}\n")

if __name__ == "__main__":
    app = ReconMate()
    app.mainloop()