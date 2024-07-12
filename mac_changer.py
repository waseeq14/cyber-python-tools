#!/usr/bin/env python

import subprocess
import optparse
import argparse
import re

# parser = optparse.OptionParser()
# parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC", metavar="INTERFACE")
# parser.add_option("-m", "--mac", dest="newMac", help="New MAC address", metavar="NEW MAC")
# (options, args) = parser.parse_args()
# interface = options.interface
# newMac = options.newMac
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change it's MAC", metavar="INTERFACE")
    parser.add_argument("-m", "--mac", dest="newMac", help="new MAC address", metavar="NEW MAC")
    args = parser.parse_args()
    if not args.interface:
        parser.error("[-] Please enter an interface, use --help for more info")
        return
    elif not args.newMac:
        parser.error("[-] Please enter the new Mac address, use --help for more info")
        return
    else:
        return args

def change_mac(interface, newMac):
    print("[+] Changing MAC address of "+interface+" to "+newMac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", newMac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    result = subprocess.check_output(["ifconfig", interface])
    current_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(result))
    if current_mac:
        return current_mac.group(0)
    else:
        print("[-] Couldn't get the MAC address of "+interface)


args = get_arguments()
current_mac = str(get_current_mac(args.interface))
print("Current MAC: "+current_mac)
change_mac(args.interface, args.newMac)
current_mac = str(get_current_mac(args.interface))
if current_mac == args.newMac:
    print("[+] MAC changed to: "+current_mac)
else:
    print("[-] Error changing MAC address!")
