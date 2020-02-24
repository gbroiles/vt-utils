""" utility functions for virustotal API """
import hashlib
import json
import requests

HEXCHARS = "0123456789abcdef"


def scan(filename, apikey):
    """ checks virustotal for given filename hash for pre-generated reports """
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    if len(filename) == 64 and all(x in filename for x in HEXCHARS):
        sha256 = filename
    else:
        with open(filename, "rb") as infile:
            contents = infile.read()
        sha256 = hashlib.sha256(contents).hexdigest()
    params = {"apikey": apikey, "resource": sha256, "allinfo": True}
    response = requests.get(url, params=params)
    return json.loads(response.text)
