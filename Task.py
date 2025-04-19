# First of all i installed both scapy and pyshark using the command lin 'pip install scapy
# '''in the venv/bin/activate'''

import scapy
from scapy.all import *

# Function to handle each packet
def handle_packet(packet, log):

    # Check if the packet contains TCP layer
    if packet.haslayer(TCP):
        print(TCP)

        # Extract source and destination IP addresses
        source_ip = packet[IP].source
        destination_ip = packet[IP].destination

        # Extract source and destination ports
        source_port = packet[TCP].sourceport
        destination_port = packet[TCP].destinationport
        
        # Write packet information to log file
        log.write(f"TCP Connection: {source_ip}:{source_port} -> {destination_ip}:{destination_port}\n")
        
        
# Main function to start packet sniffing
def main(interface, verbose=False):
    
    # Create log file name based on interface
    logfile_name = f"sniffer_{interface}_log.txt"
    
    # Open log file for writing
    with open(logfile_name, 'w') as logfile:
        try:
            
            # Start packet sniffing on specified interface with verbose output
            if verbose:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
            else:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)
            
# Check if the script is being run directly
if __name__ == "__main__":
    
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
        
    #Determine if verbose mode is enabled
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
        
    # Call the main function with the specified interface and verbose option
    main(sys.argv[1], verbose)