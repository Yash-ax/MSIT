import scapy 
from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"\n[+] Packet captured:")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        print(f"    Protocol: {protocol}")
        
        # Check for TCP/UDP and print port numbers
        if protocol == 6:  # TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"    Source Port: {src_port}")
            print(f"    Destination Port: {dst_port}")
        elif protocol == 17:  # UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"    Source Port: {src_port}")
            print(f"    Destination Port: {dst_port}")
        
        # Check for payload data and display it
        if Raw in packet:
            payload_data = packet[Raw].load
            print(f"    Payload: {payload_data[:50]}...")  # Limiting to 50 bytes for display

def start_sniffing(interface):
    print(f"[*] Starting packet sniffer on interface {interface}")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    # Change 'eth0' to the network interface you want to sniff (e.g., 'wlan0' for Wi-Fi on Linux)
    network_interface = input("Enter the network interface you want to sniff (e.g., 'eth0', 'wlan0'): ")
    start_sniffing(network_interface)
