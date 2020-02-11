#! /usr/bin/env python3
#pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring
import argparse
import hashlib
import os
import sys
import pprint
import requests

def create_parse():
    parser = argparse.ArgumentParser(
        description='virustotal file report retriever')
    parser.add_argument('filename', help='file to check for results')
    return parser


def scanit(filename, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    f = open(filename, "rb")
    contents = f.read()
    sha256 = hashlib.sha256(contents).hexdigest()
    params = {'apikey': apikey, 'resource': sha256, 'allinfo': True}
    response = requests.get(url, params=params)
    pprint.pprint(response.json())

def start():
    parser = create_parse()
    args = parser.parse_args()
    try:
        apikey = os.environ["VTAPI"]
    except KeyError:
        print('Must set VTAPI key enviroment variable.')
        sys.exit(1)
    scanit(args.filename, apikey)

if __name__ == '__main__':
    start()
