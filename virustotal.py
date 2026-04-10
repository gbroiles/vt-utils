""" utility functions for virustotal API """
import hashlib
import requests

HEXCHARS = "0123456789abcdef"


def scan(filename, apikey):
    """ checks virustotal for given filename hash for pre-generated reports """
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    normalized = filename.lower()
    count = len(normalized)
    if (count == 64 or count == 40 or count == 32) and all(
        x in HEXCHARS for x in normalized
    ):
        print("Treating {} as a hash, not as a filename".format(filename))
        resource = normalized
    elif (
        count == 75
        and normalized[64] == "-"
        and all(x in HEXCHARS for x in normalized[:64] + normalized[65:])
    ):
        print("Treating {} as a VirusTotal scan ID, not as a filename".format(filename))
        resource = normalized
    else:
        with open(filename, "rb") as infile:
            contents = infile.read()
        resource = hashlib.sha256(contents).hexdigest()
    params = {"apikey": apikey, "resource": resource, "allinfo": True}
    response = requests.get(url, params=params)
    response.raise_for_status()
    return response.json()
