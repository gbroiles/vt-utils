#! /usr/bin/env python3
""" command line utility to check virustotal for reports re a file or sha256 hash """
import argparse
import os
import sys
import pprint
import virustotal


def create_parse():
    """ set up CLI parser """
    parser = argparse.ArgumentParser(description="virustotal file report retriever")
    parser.add_argument("filename", help="file(s) to check for results", nargs="+")
    return parser


def start():
    """ main work done here """
    parser = create_parse()
    args = parser.parse_args()
    try:
        apikey = os.environ["VTAPI"]
    except KeyError:
        print("Must set VTAPI key enviroment variable.")
        sys.exit(1)
    for item in args.filename:
        response = virustotal.scan(item, apikey)
        pprint.pprint(response)


if __name__ == "__main__":
    start()
