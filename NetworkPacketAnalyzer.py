from scapy.all import sniff, IP, TCP, UDP, Raw


class PacketAnalyzer:
    def __init__(self, packet_count=10):
        """
        Initialise the packet sniffer with the desired number of packets to capture.
        """
        self.packet_count = packet_count

    def analyse_packet(self, packet):
        """
        Callback function to process and display captured packets.
        """
        print("\n=== Packet Captured ===")

        # Extract IP Layer information
        if IP in packet:
            print(f"Source IP: {packet[IP].src}")
            print(f"Destination IP: {packet[IP].dst}")
            print(f"Protocol number: {packet[IP].proto}")

        # Extract TCP/UDP Layer information
        if TCP in packet or UDP in packet:
            protocol = "TCP" if TCP in packet else "UDP"
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            print(f"Protocol: {protocol}")
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")

        # Extract Payload Data if available
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")

    def start_sniffing(self, interface=None):
        """
        Start capturing packets on the specified interface or default interface.
        """
        print(f"Starting packet capture... Capturing {self.packet_count} packets.")
        sniff(count=self.packet_count, iface=interface, prn=self.analyse_packet, store=0)


if __name__ == "__main__":
    print("=== Network Packet Analyzer ===")
    interface = input("Enter the network interface to capture packets (leave blank for default): ").strip() or None

    # Create an instance of PacketAnalyzer and start sniffing
    analyzer = PacketAnalyzer(packet_count=10)
    analyzer.start_sniffing(interface)
