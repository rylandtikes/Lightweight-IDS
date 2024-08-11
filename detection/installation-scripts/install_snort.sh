#!/bin/bash

SNORT_VERSION="2.9.20"
DAQ_VERSION="2.0.7"
INSTALL_DIR="/usr/local"
SNORT_CONF="/etc/snort/snort.conf"
SNORT_LOG_DIR="/var/log/snort"
COMMUNITY_RULES_URL="https://www.snort.org/downloads/community/community-rules.tar.gz"

echo "Updating the system..."
sudo apt-get update && sudo apt-get upgrade -y
echo "Installing dependencies..."
sudo apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev wget libluajit-5.1-dev libtirpc-dev
echo "Removing existing Snort installation..."
sudo systemctl stop snort
sudo systemctl disable snort
sudo rm -rf $INSTALL_DIR/bin/snort /usr/sbin/snort /etc/snort /var/log/snort $INSTALL_DIR/lib/snort_dynamicrules
sudo rm -rf snort-${SNORT_VERSION} snort-${SNORT_VERSION}.tar.gz daq-${DAQ_VERSION} daq-${DAQ_VERSION}.tar.gz


echo "Downloading and installing DAQ version $DAQ_VERSION..."
wget https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz
tar -xvzf daq-${DAQ_VERSION}.tar.gz
cd daq-${DAQ_VERSION}
./configure --prefix=${INSTALL_DIR}
make
sudo make install
cd ..


echo "Downloading Snort version $SNORT_VERSION..."
wget https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz
tar -xvzf snort-${SNORT_VERSION}.tar.gz
cd snort-${SNORT_VERSION}


export CFLAGS="-I/usr/include/tirpc"
export LDFLAGS="-ltirpc"


echo "Compiling and installing Snort..."
./configure --prefix=${INSTALL_DIR} --enable-sourcefire --disable-open-appid
make
sudo make install
sudo ldconfig


echo "Updating PATH for Snort and DAQ..."
echo "export PATH=\$PATH:${INSTALL_DIR}/bin" | sudo tee /etc/profile.d/snort-daq.sh
. /etc/profile.d/snort-daq.sh

echo "Verifying Snort installation..."
if command -v snort >/dev/null 2>&1; then
    echo "Snort successfully installed."
else
    echo "Snort installation failed."
    exit 1
fi


echo "Creating necessary directories..."
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /etc/snort/preproc_rules
sudo mkdir -p /var/log/snort
sudo mkdir -p ${INSTALL_DIR}/lib/snort_dynamicrules

echo "Copying configuration files..."
sudo cp etc/*.conf* /etc/snort
sudo cp etc/*.map /etc/snort
sudo cp etc/*.dtd /etc/snort


echo "Downloading Snort community rules..."
wget $COMMUNITY_RULES_URL -O community-rules.tar.gz
tar -xvzf community-rules.tar.gz -C /etc/snort/rules --strip-components=1


echo "Configuring snort.conf..."
sudo sed -i 's|^var RULE_PATH .*|var RULE_PATH /etc/snort/rules|' /etc/snort/snort.conf
sudo sed -i 's|^var SO_RULE_PATH .*|var SO_RULE_PATH /etc/snort/so_rules|' /etc/snort/snort.conf
sudo sed -i 's|^var PREPROC_RULE_PATH .*|var PREPROC_RULE_PATH /etc/snort/preproc_rules|' /etc/snort/snort.conf
sudo sed -i 's|^var WHITE_LIST_PATH .*|var WHITE_LIST_PATH /etc/snort/rules|' /etc/snort/snort.conf
sudo sed -i 's|^var BLACK_LIST_PATH .*|var BLACK_LIST_PATH /etc/snort/rules|' /etc/snort/snort.conf
sudo sed -i 's|^ipvar HOME_NET .*|ipvar HOME_NET any|' /etc/snort/snort.conf
sudo sed -i 's|^ipvar EXTERNAL_NET .*|ipvar EXTERNAL_NET !$HOME_NET|' /etc/snort/snort.conf


echo "Testing Snort configuration..."
sudo snort -T -c /etc/snort/snort.conf -i eth0


echo "Creating systemd service for Snort..."
sudo bash -c 'cat << EOF > /etc/systemd/system/snort.service
[Unit]
Description=Snort NIDS Daemon
After=network.target

[Service]
ExecStart=/usr/sbin/snort -c /etc/snort/snort.conf -i eth0
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
EOF'

echo "Enabling and starting Snort service..."
sudo systemctl daemon-reload
sudo systemctl enable snort
sudo systemctl start snort

echo "Snort installation and setup complete."
