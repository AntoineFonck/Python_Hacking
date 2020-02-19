#!/usr/bin/env python

import scapy.all as scapy
from optparse import OptionParser


def get_options():
    """Get options from the args parser"""
    parser = OptionParser()
    parser.add_option(
        "-t",
        "--target_ip",
        dest="target_ip",
        help="Target ip or ip range to scan",
        metavar="TARGET_IP / RANGE_IP"
    )

    (options, args) = parser.parse_args()
    if not options.target_ip:
        parser.error("Missing target IP, use -h or --help for more info")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    full_request = broadcast/arp_request
    answered = scapy.srp(full_request, timeout=1, verbose=False)[0]
    client_lst = []
    for elem in answered:
        client_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        client_lst.append(client_dict)
    return client_lst


def print_client_lst(client_lst):
    print("IP\t\t\tMAC ADDRESS\n------------------------------------------------")
    for client in client_lst:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_options()
client_lst = scan(options.target_ip)
print_client_lst(client_lst)
