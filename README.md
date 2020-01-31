# vt-utils
VirusTotal command line utilities

A simple command line wrapper for the VirusTotal API.

Prior to use, the environment variable VTAPI must be set to your VirusTotal API key.

For example: place `export VTAPI="blahblahblah"` in .bashrc

## Usage:

`vt-upload suspicious.exe`
  uploads file "suspicious.exe" to VirusTotal for analysis
  
`vt-report suspicious.exe`
  checks VirusTotal for analysis/reports re file "suspicious.exe"
