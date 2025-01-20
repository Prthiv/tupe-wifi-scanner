# Tupe-scanner 📶

**Tupe-scanner** is a beginner-friendly Wi-Fi scanner tool designed to scan nearby Wi-Fi networks and display details such as:
- **SSID** (Wi-Fi name)
- **Signal Strength**
- **Encryption Type**

## Features
- Works on Linux, macOS, and Windows (with limited functionality on Windows).
- Uses Python and Scapy for powerful packet capturing and analysis.
- Displays a user-friendly menu interface.

## Requirements
1. **Python Version**:
   - Python 3.6 or higher.

2. **Dependencies**:
   - `scapy`

3. **Operating System**:
   - **Linux**: Full functionality, requires monitor mode enabled.
   - **macOS**: Partial functionality, monitor mode required.
   - **Windows**: General packet sniffing only (no Dot11 support).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Prthiv/Tupe-scanner.git
   cd Tupe-scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:
   ```bash
   sudo python3 tupe_scanner.py
   ```

## Usage

1. **Enable Monitor Mode** (Linux/macOS):
   ```bash
   sudo ifconfig wlan0 down
   sudo iwconfig wlan0 mode monitor
   sudo ifconfig wlan0 up
   ```
   Replace `wlan0` with your Wi-Fi interface name.

2. **Start the Scanner**:
   ```bash
   sudo python3 tupe_scanner.py
   ```

3. Follow the menu prompts:
   - Enter your Wi-Fi interface name (e.g., `wlan0`).
   - View nearby Wi-Fi networks with SSID, signal strength, and encryption type.

## Troubleshooting

1. **Permission Denied**:
   Run the script with `sudo` to grant the necessary permissions.

2. **Invalid Interface**:
   Use `ifconfig` or `iwconfig` to verify your Wi-Fi interface name.

3. **No Packets Captured**:
   Ensure monitor mode is enabled and there are active Wi-Fi networks nearby.

4. **Windows Issues**:
   Only general packet sniffing is supported on Windows.

## License
This tool is for educational purposes only. Use responsibly.

## Contact
For questions or contributions, contact on [GitHub](https://github.com/Prthiv).