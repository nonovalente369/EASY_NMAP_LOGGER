EASY NMAP LOGGER 🛡️
A lightweight, Python-based network security analyzer designed to detect and log common Nmap scanning techniques. This tool uses Scapy for deep packet inspection and Socket programming to create a functional honeypot "trap."

🚀 Features
Multi-Layer Analysis: * Layer 3 (Network): Detects ICMP "Ping" discoveries.

Layer 4 (Transport): Identifies TCP and UDP port scans, including stealth flags.

Layer 7 (Application): Performs Deep Packet Inspection (DPI) to find service version probes (HTTP, SSH, etc.).

Active Honeypot: Opens a "Trap" port (Default: 8000) that listens for connection attempts and logs fingerprinting data.

Automatic Summarization: The protocol_recognizer engine summarizes port ranges hit by an attacker after they go inactive.

Thread-Safe: Uses threading.Lock to handle high-traffic environments without data collisions.

🛠️ Requirements
Python 3.x

Scapy (pip install scapy)

Root/Administrator privileges (required for packet sniffing)

📖 How it Works
The tool runs three parallel threads:

Watchdog: Sniffs incoming traffic and extracts headers from the IP, TCP, and UDP layers. It looks for "Stealth" flags like Null, Xmas, and Fin scans.

Port Trap: A live socket that acts as bait. It accepts connections and records any "Version Fingerprinting" messages the attacker's tools send.

Analyzer: Every 10 seconds, it checks the history and prints a clean report of which IP addresses were scanning which port ranges.

🚦 Usage
Clone the repository:

Bash

git clone https://github.com/nonovalente369/EASY_NMAP_LOGGER.git
cd EASY_NMAP_LOGGER
Run with sudo/admin:

Bash

sudo python3 your_script_name.py
⚠️ Disclaimer
This tool is for educational and defensive purposes only. Use it only on networks you own or have explicit permission to monitor.
