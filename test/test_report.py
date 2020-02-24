import os
import sys
import virustotal
import vt_report

testfile = "eicar.com"

try:
    apikey = os.environ["VTAPI"]
except KeyError:
    print("Must set VTAPI key enviroment variable.")
    assert 0

result = virustotal.scan(testfile,apikey)

assert 'md5' in result
assert 'permalink' in result
assert 'scans' in result
assert 'sha1' in result
assert result['sha256'] == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

