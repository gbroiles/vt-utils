# pylint: disable=invalid-name,missing-module-docstring,missing-function-docstring
import os
import virustotal

#testfile = "eicar.com"
eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

def check_positive(result):
    assert "md5" in result
    assert "permalink" in result
    assert "scans" in result
    assert "sha1" in result
    assert result["sha256"] == eicar_sha256

try:
    apikey = os.environ["VTAPI"]
except KeyError:
    print("Must set VTAPI key enviroment variable.")
    assert 0

#test_positive_result(virustotal.scan(testfile, apikey))  # test with EICAR file
# eicar file disabled because it makes Travis-CI angry
result = virustotal.scan(eicar_sha256, apikey)  # test with EICAR hash
check_positive(result)
