# ReconMate

ReconMate is a versatile reconnaissance tool with a GUI built using `customtkinter`. It allows users to perform basic port scanning and subdirectory enumeration, making it a great utility for penetration testers, cybersecurity enthusiasts, and developers interested in recon tasks.

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
   git clone https://github.com/<your-username>/ReconMate.git
   cd ReconMate
