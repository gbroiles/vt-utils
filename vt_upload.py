#! /usr/bin/env python3
# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring
import argparse
import os
import sys
import pprint
import requests


def create_parse():
    parser = argparse.ArgumentParser(description="virustotal file uploader")
    parser.add_argument("filename", help="file(s) to scan", nargs="+")
    return parser


def scanit(filename, apikey):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {"apikey": apikey}
    with open(filename, "rb") as fh:
        files = {"file": (filename, fh)}
        response = requests.post(url, files=files, params=params)
    response.raise_for_status()
    result = response.json()
    vtlog = os.environ.get("VTLOG")
    if vtlog:
        try:
            with open(vtlog, "a") as f:
                f.write(str(result) + "\n")
        except Exception as e:
            print("Error: ", e)
    pprint.pprint(result)


def start():
    parser = create_parse()
    args = parser.parse_args()
    try:
        apikey = os.environ["VTAPI"]
    except KeyError:
        print("Must set VTAPI key environment variable.")
        sys.exit(1)

    for item in args.filename:
        scanit(item, apikey)


if __name__ == "__main__":
    start()
