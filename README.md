# Network Packet Analyzer

## Overview
The Network Packet Analyzer is a Python tool that captures and analyses network packets. Designed for educational purposes, it displays key information such as IP addresses, protocols, ports, and payload data.

## Features

- **Packet Capturing:** Captures a specified number of network packets.
- **Protocol Analysis:** Extracts and displays source/destination IPs, protocols (TCP/UDP), and port numbers.
- **Payload Inspection:** Shows payload data when available.
- **Customisable Interface:** Allows selection of network interface and packet count.

## Requirements
- Python 3.6 or later
- `scapy` library

## Installation
1. Install Python from [python.org](https://www.python.org/).
2. Install the `scapy` library:
   ```bash
   pip install scapy
   ```

## Usage
1. Save the program as `NetworkPacketAnalyzer.py`.
2. Run the program:
   ```bash
   python NetworkPacketAnalyzer.py
   ```
3. Specify the network interface (e.g., `eth0`) or leave blank for the default.
4. View packet details in the console.

## Ethical Considerations
Use this tool responsibly on authorised networks. Unauthorised packet capturing may violate laws or ethical guidelines. This project is intended for educational and authorised testing purposes only.

