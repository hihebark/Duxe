#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import re

from core.log import *
from core.version import *

def banner():
    return "  Duxe - "+red(VERSION)+green(" ~ Beta")

if __name__ == "__main__":
    print(banner())
    parser = argparse.ArgumentParser(description="Duxe - Information gathering tool.")
    parser.add_argument("-host", help="Host for the information gathering.")
    parser.add_argument("-version", help="Print version and exit", action="store_true")
    args = parser.parse_args()
    if args.version:
        print("\t"+banner()+"\t["+AUTHOR+"]")
    host = args.host
    print(blue("- Host: "+host))
    print("checking connectivity to the host:")
    if requests.get(host).status_code == 200:
        print(green("Ok!"))
    else:
        print(yellow("No connection found!"))
