from scapy.all import sniff, wrpcap, get_if_list
from datetime import datetime
import csv
import sys
import os

captured_packets = []

def analyze_packet(packet):
    print(packet.summary())
    captured_packets.append(packet)

def save_to_pcap(filename):
    wrpcap(filename, captured_packets)
    print(f"[+] Packets saved to {filename}")

def save_to_csv(filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "Source", "Destination", "Protocol", "Summary"])
        for pkt in captured_packets:
            writer.writerow([
                pkt.time,
                pkt[0].src if hasattr(pkt[0], "src") else "N/A",
                pkt[0].dst if hasattr(pkt[0], "dst") else "N/A",
                pkt.name,
                pkt.summary()
            ])
    print(f"[+] Summary saved to {filename}")

def main():
    print("Available Interfaces:", ", ".join(get_if_list()))
    interface = input("Enter the interface to sniff (e.g., eth0): ").strip()
    protocol = input("Enter protocol to filter (tcp, udp, icmp, or all): ").strip().lower()

    if protocol == "all":
        bpf_filter = ""
    elif protocol in ["tcp", "udp", "icmp"]:
        bpf_filter = protocol
    else:
        print("[!] Invalid protocol. Use tcp, udp, icmp, or all.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"capture_{protocol}_{timestamp}.pcap"
    csv_file = f"capture_{protocol}_{timestamp}.csv"

    print(f"[*] Starting capture on {interface} with filter: '{bpf_filter}'... Press Ctrl+C to stop.")
    
    try:
        sniff(iface=interface, prn=analyze_packet, filter=bpf_filter, store=False)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
        save_to_pcap(pcap_file)
        save_to_csv(csv_file)
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run this script as root (e.g., with sudo).")
        sys.exit(1)
    main()
