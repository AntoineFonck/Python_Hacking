#!/usr/bin/env python

from subprocess import call, check_output, CalledProcessError
from platform import system
from optparse import OptionParser
import re


def get_options():
    """Get options from the args parser"""
    parser = OptionParser()
    parser.add_option(
        "-i",
        "--interface",
        dest="interface",
        help="Interface of which the MAC address will be modified",
        metavar="INTERFACE"
    )

    parser.add_option(
        "-m",
        "--mac",
        dest="new_mac",
        help="The new mac address",
        metavar="NEW_MAC"
    )
    (options, args) = parser.parse_args()
    if not options.interface or not options.new_mac:
        parser.error("Missing interface or new mac address, use -h or --help for more info")
    return options


def change_mac(interface, new_mac):
    """Try to modify the given interface's MAC address"""
    print("[+] Modifying " + interface + " MAC address to " + new_mac)
    if system() == "Linux":
        call(["ifconfig", interface, "down"])
        call(["ifconfig", interface, "hw", "ether", new_mac])
        call(["ifconfig", interface, "up"])
    elif system() == "Darwin":
        call(["ifconfig", interface, "ether", new_mac])
    else:
        exit(0)


def get_current_mac(interface):
    try:
        ifconfig_output = check_output(["ifconfig", options.interface])
    except CalledProcessError as e:
        print(e.output)
        exit(1)
    current_mac_address_found = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_output))
    if current_mac_address_found:
        return current_mac_address_found.group(0)
    else:
        print("[-] MAC address of " + options.interface + " could not be read")


options = get_options()
print("[+] Previous MAC address " + str(get_current_mac(options.interface)))
change_mac(options.interface, options.new_mac)
if str(get_current_mac(options.interface)) == options.new_mac:
    print("[+] MAC address was successfully changed to: " + options.new_mac)
else:
    print("[-] MAC address was not modified")
