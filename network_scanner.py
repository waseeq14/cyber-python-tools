#!/usr/bin/env python
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", dest="Range", help="Range of IPs to scan", metavar="RANGE")
    args = parser.parse_args()
    if not args.Range:
        parser.error("[-] Enter a valid IP Range!. Use -h or --help for more info!")
        return
    else:
        return args

def scan(ip):
    packet = scapy.ARP(pdst=ip)
    frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = frame/packet
    answered_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]
    result = []
    for x in answered_list:
        dict = {"mac": x[1].hwsrc, "ip": x[1].psrc}
        result.append(dict)
    return result

def print_result(result):
    print("IP ADDRESS\t\tMAC ADDRESS\n-------------------------------------------")
    for x in result:
        print(x["ip"] + "\t\t" + x["mac"])


args = get_arguments()
result_list = scan(args.Range)
print_result(result_list)
