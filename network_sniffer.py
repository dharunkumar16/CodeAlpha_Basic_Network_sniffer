from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffer(interface=None, count=10):
    print(f"Starting network sniffer on interface: {interface if interface else 'default'}")
    sniff(iface=interface, prn=packet_callback, count=count, store=False)

if __name__ == "__main__":
    interface = input("Enter network interface (leave blank for default): ") or None
    packet_count = int(input("Enter number of packets to capture: "))
    start_sniffer(interface, packet_count)
