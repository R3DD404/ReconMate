## ReconMate

ReconMate is a versatile reconnaissance tool made for CTFs with a GUI built using `customtkinter`. It allows users to perform basic port scanning and subdirectory enumeration, making it a great utility for CTF participants, penetration testers, and cybersecurity enthusiasts focused on capture-the-flag challenges.

---

## Features

- **Port Scanning**:
  - Scans common ports for open services.
  - Recommends an `nmap` command for deeper exploration of discovered ports.
  
- **Subdirectory Enumeration**:
  - Uses a wordlist to find directories on a target web server.

- **Modern GUI**:
  - Dark mode design with progress indicators.
  - Sidebar navigation for ease of use.

- **Stop and Clear Options**:
  - Stop scans midway or clear the results panel to start afresh.

---

## Installation

### Prerequisites

- Python 3.8 or later
- `pip` package manager

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/R3DD404/ReconMate.git
   cd ReconMate
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run ReconMate:
   ```bash
   python recon.py
   ```

---

## Usage

1. **Port Scanning**
   - Enter the target IP address or domain.
   - Click "Start Scan" to initiate port scanning.
   - Review open ports and suggested `nmap` commands for deeper scans.

2. **Subdirectory Enumeration**
   - Provide the target URL.
   - Upload or select a wordlist for directory fuzzing.
   - View discovered directories and their HTTP status codes.

3. **Stopping or Clearing**
   - Use the "Stop" button to halt ongoing scans.
   - Click "Clear" to reset the results panel.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Contact

For questions or feedback, reach out via GitHub issues.

---

Happy hacking! 🚀

