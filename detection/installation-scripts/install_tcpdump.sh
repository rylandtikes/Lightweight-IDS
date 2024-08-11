#!/bin/bash

echo "Updating the system..."
sudo apt-get update && sudo apt-get upgrade -y

echo "Installing tcpdump..."
sudo apt-get install -y tcpdump

echo "Verifying tcpdump installation..."
if command -v tcpdump >/dev/null 2>&1; then
    echo "tcpdump successfully installed."
    tcpdump --version
else
    echo "Failed to install tcpdump."
    exit 1
fi
