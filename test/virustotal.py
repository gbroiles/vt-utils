import hashlib
import json
import requests

def scan(filename, apikey):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    with open(filename, "rb") as f:
        contents = f.read()
    sha256 = hashlib.sha256(contents).hexdigest()
    params = {"apikey": apikey, "resource": sha256, "allinfo": True}
    response = requests.get(url, params=params)
    response_dict = json.loads(response.text)
    return response_dict
