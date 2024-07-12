#!usr/bin/env python

import scapy.all as scapy

def get_mac(ip):
    packet = scapy.ARP(pdst=ip)
    frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = frame/packet
    answer_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]
    mac = answer_list[0][1].hwsrc
    return mac


def process(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        real_mac = get_mac(packet[scapy.ARP].psrc)
        mac_coming = packet[scapy.ARP].hwsrc
        if mac_coming != real_mac:
            print("[!]ARP Spoof possibly by: "+mac_coming)

def sniff(interface):
    scapy.sniff(store=False, prn=process, iface=interface)


sniff('wlan0') #any interface

