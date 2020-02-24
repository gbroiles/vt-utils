""" utility functions for virustotal API """
import hashlib
import json
import requests


def scan(filename, apikey):
    """ checks virustotal for given filename hash for pre-generated reports """
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    with open(filename, "rb") as infile:
        contents = infile.read()
    sha256 = hashlib.sha256(contents).hexdigest()
    params = {"apikey": apikey, "resource": sha256, "allinfo": True}
    response = requests.get(url, params=params)
    response_dict = json.loads(response.text)
    return response_dict
