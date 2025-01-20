import os
import time
import platform
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon
import socket

def banner():
    """
    Displays the banner for the tool.
    """
    print("=" * 50)
    print(" " * 14 + "Tupe-scanner 📶")
    print("=" * 50)
    print("Created by: Your Name (GitHub: YourGitHubUsername)\n")
    print("Scan nearby Wi-Fi networks and display details such as:")
    print("SSID, Signal Strength, and Encryption Type.\n")
    print("=" * 50)

def menu():
    """
    Displays the main menu options.
    """
    print("\n[1] Start Wi-Fi Scanner")
    print("[2] About Tupe-scanner")
    print("[3] Exit\n")

def wifi_scanner_linux_mac(interface):
    """
    Scans for nearby Wi-Fi networks on Linux/macOS.
    """
    networks = {}

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11].info.decode(errors="ignore")
            bssid = packet[Dot11].addr2
            signal_strength = packet.dBm_AntSignal
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
            encryption = "WPA/WPA2" if "WPA" in cap else "WEP" if "WEP" in cap else "Open"
            
            if bssid not in networks:
                networks[bssid] = (ssid, signal_strength, encryption)
                print(f"SSID: {ssid:<20} | Signal: {signal_strength:>4}dBm | Encryption: {encryption}")

    try:
        print(f"\n[+] Scanning on interface '{interface}'...")
        print("-" * 50)
        sniff(iface=interface, prn=packet_handler, timeout=30)
        print("-" * 50)
        print("\n[+] Scan completed.")
    except PermissionError:
        print("[Error] Root permissions are required to run this script.")
    except OSError:
        print(f"[Error] Invalid interface '{interface}'. Please check and try again.")
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")

def wifi_scanner_windows():
    """
    Scans for general network packets on Windows.
    """
    try:
        print("\n[+] Scanning on Windows (general packets only)...")
        print("-" * 50)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        s.bind((ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        for _ in range(10):  # Capture 10 packets as an example
            packet = s.recvfrom(65565)
            print(f"Packet received: {packet}")
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("-" * 50)
        print("\n[+] Scan completed.")
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")

def about():
    """
    Displays information about the tool.
    """
    print("\nTupe-scanner is a beginner-friendly Wi-Fi scanner tool.")
    print("It allows you to scan nearby Wi-Fi networks and get details such as:")
    print(" - SSID (Wi-Fi name)")
    print(" - Signal strength")
    print(" - Encryption type\n")
    print("Built with Python and Scapy.\n")
    print("GitHub: https://github.com/YourGitHubUsername/Tupe-scanner")

def main():
    """
    Main function to handle the tool's interface and functionality.
    """
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        banner()
        menu()
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            system = platform.system()
            if system in ["Linux", "Darwin"]:  # Linux or macOS
                interface = input("\nEnter your Wi-Fi interface name (e.g., wlan0): ").strip()
                if not interface:
                    print("[Error] No input provided. Please enter a valid Wi-Fi interface name.")
                    time.sleep(2)
                    continue
                wifi_scanner_linux_mac(interface)
            elif system == "Windows":
                wifi_scanner_windows()
            else:
                print("[Error] Unsupported operating system.")
            input("\nPress Enter to return to the menu...")
        elif choice == '2':
            os.system('clear' if os.name == 'posix' else 'cls')
            about()
            input("\nPress Enter to return to the menu...")
        elif choice == '3':
            print("\nThank you for using Tupe-scanner! Goodbye!")
            break
        else:
            print("[Error] Invalid choice. Please select a valid option.")
            time.sleep(2)

if __name__ == "__main__":
    main()
