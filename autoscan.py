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
    (options, args) = parser.parse_args()
    if not options.target:
        parser.error("Missing target, use -h or --help for more info")
    return options


all_options = get_options()
autoscan = Autoscan(all_options.target)
autoscan.run()
