#!/usr/bin/env python3

from Autoscan_class import Autoscan
from optparse import OptionParser


def get_options():
    """Get options from the args parser"""
    parser = OptionParser()
    parser.add_option(
        "-t",
        "--target",
        dest="target",
        help="target to scan",
        metavar="TARGET"
    )
    parser.add_option(
        "-d",
        "--directory",
        dest="directory",
        help="specific directory to scan",
        metavar="DIRECTORY"
    )
    parser.add_option(
        "-u",
        "--auth",
        dest="authentication",
        help="HTTP Basic auth in the form user:pass",
        metavar="AUTHENTICATION"
    )
    (options, args) = parser.parse_args()
    if not options.target:
        parser.error("Missing target, use -h or --help for more info")
    return options


all_options = get_options()
if all_options.authentication is not None:
    username = all_options.authentication.split(":")[0]
    password = all_options.authentication.split(":")[1]
else:
    username = None
    password = None
if all_options.directory is not None:
    directory = all_options.directory
else:
    directory = None
autoscan = Autoscan(all_options.target, directory=directory, user=username, password=password)
autoscan.run()
