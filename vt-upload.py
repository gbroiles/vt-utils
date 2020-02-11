#! /usr/bin/env python3
import requests
import argparse
import os,sys
import pprint

def create_parse():
    parser = argparse.ArgumentParser(
        description='virustotal file uploader')
    parser.add_argument('filename', help='file to scan')
    return parser


def scanit(filename,apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': (filename, open(filename, 'rb'))}
    response = requests.post(url, files=files, params=params)
    pprint.pprint(response.json())

def start():
    parser = create_parse()
    args = parser.parse_args()
    filename = args.filename
    try:
        apikey = os.environ["VTAPI"]
    except KeyError:
        print('Must set VTAPI key enviroment variable.')
        sys.exit(1)

    scanit(args.filename,apikey)


if __name__ == '__main__':
    start()

