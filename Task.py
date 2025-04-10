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