#! /usr/bin/env python3
import requests
import argparse
import hashlib
import os,sys
import pprint

def create_parse():
    parser = argparse.ArgumentParser(
        description='virustotal file report retriever')
    parser.add_argument('filename', help='file to check for results')
    return parser


def scanit(filename):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    apikey = os.environ["VTAPI"]
    f = open(filename, "rb")
    contents=f.read()
    sha256=hashlib.sha256(contents).hexdigest()
#    print(sha256)
    params = {'apikey': apikey, 'resouce': sha256}
    response = requests.get(url, params=params)
    status = response.status_code
    print(status)
    pprint.pprint(response.json())

def start():
    parser = create_parse()
    args = parser.parse_args()
    filename = args.filename
    if os.environ['VTAPI'] == "":
        print('Must set VTAPI key enviroment variable.')
        sys.exit
    scanit(args.filename)


if __name__ == '__main__':
    start()

