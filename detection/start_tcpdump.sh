#!/bin/bash

INTERFACE="eth0"
PCAP_DIR="/home/rtikes/pcap"
PCAP_FILE="${PCAP_DIR}/traffic.pcap0"

echo "Creating pcap directory if it doesn't exist..."
mkdir -p $PCAP_DIR

echo "Changing ownership and permissions of the pcap directory..."
chown $USER:$USER $PCAP_DIR
chmod 755 $PCAP_DIR

echo "Verifying directory ownership and permissions..."
ls -ld $PCAP_DIR

echo "Starting tcpdump..."
sudo tcpdump -i $INTERFACE -C 5000 -W 2 -w ${PCAP_FILE} &
TCPDUMP_PID=$!
echo "tcpdump started with PID $TCPDUMP_PID"

stop_tcpdump() {
  if [ ! -z "$TCPDUMP_PID" ]; then
    echo "Stopping tcpdump..."
    sudo kill $TCPDUMP_PID
  fi
}

trap "stop_tcpdump; exit" SIGINT SIGTERM

wait $TCPDUMP_PID
