from scapy.all import IP, TCP, UDP, DNS, Ether, Raw, HTTP

def parse_packet(pkt):
    packet_info = {}
    
    if Ether in pkt:
        packet_info['protocol'] = pkt.lastlayer().name
    if IP in pkt:
        packet_info['src_ip'] = pkt[IP].src
        packet_info['dst_ip'] = pkt[IP].dst
    if TCP in pkt:
        packet_info['src_port'] = str(pkt[TCP].sport)
        packet_info['dst_port'] = str(pkt[TCP].dport)
    elif UDP in pkt:
        packet_info['src_port'] = str(pkt[UDP].sport)
        packet_info['dst_port'] = str(pkt[UDP].dport)
    
    if Raw in pkt:
        packet_info['payload'] = str(pkt[Raw].load)
    else:
        packet_info['payload'] = ""

    return packet_info
