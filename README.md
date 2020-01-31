# vt-utils
VirusTotal command line utilities

command line wrapper for VirusTotal API.

set environment variable VTAPI to API key prior to use, such as:

  export VTAPI="blahblahblah"

in .bashrc

## Usage:

`vt-upload suspicious.exe`
  uploads file "suspicious.exe" to VirusTotal for analysis
  
`vt-report suspicious.exe`
  checks VirusTotal for analysis/reports re file "suspicious.exe"
