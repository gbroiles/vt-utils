""" utility functions for virustotal API """
import hashlib
import json
import requests

HEXCHARS = "0123456789abcdef"


def scan(filename, apikey):
    """ checks virustotal for given filename hash for pre-generated reports """
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    count = len(filename)
    if (count == 64 or count == 40 or count == 32) and all(
        x in filename for x in HEXCHARS
    ):
        print("Treating {} as a hash, not as a filename".format(filename))
        sha256 = filename
    elif (
        count == 75
        and filename[64] == "-"
        and all(x in filename for x in HEXCHARS + "-")
    ):
        print("Treating {} as a VirusTotal scan ID, not as a filename".format(filename))
        sha256 = filename
    else:
        with open(filename, "rb") as infile:
            contents = infile.read()
        sha256 = hashlib.sha256(contents).hexdigest()
    params = {"apikey": apikey, "resource": sha256, "allinfo": True}
    response = requests.get(url, params=params)
    return json.loads(response.text)
