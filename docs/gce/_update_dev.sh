#!/bin/sh

set -e

# Directory paths used for nogotofail.
INSTALL_DIR=/opt/nogotofail
CONFIG_DIR=/etc/nogotofail
LOG_DIR=/var/log/nogotofail

# Stop the nogotofail-mitm and other associated services if they're running.
if (ps ax | grep -v grep | grep nogotofail-mitm > /dev/null) then
sudo /etc/init.d/nogotofail-mitm stop
fi
if (ps ax | grep -v grep | grep dnsmasq > /dev/null) then
sudo /etc/init.d/dnsmasq stop
fi
if (ps ax | grep -v grep | grep openvpn > /dev/null) then
sudo /etc/init.d/openvpn stop
fi
# Remove Python files and compiled versions i.e. *.py and *.pyc files.
# TODO: Find a more elegant method for uninstalling a Python program.
#rm -rf $INSTALL_DIR
#rm -rf $CONFIG_DIR
#rm -rf $LOG_DIR
find $INSTALL_DIR -type f -name '*.py' -delete
find $INSTALL_DIR -type f -name '*.pyc' -delete

# Install toolchain dependencies
sudo apt-get update
sudo apt-get -y upgrade
#sudo apt-get -y install patch make gcc libssl-dev python-openssl liblzo2-dev libpam-dev

# Install OpenVPN and dnsmasq
#sudo apt-get -y install openvpn dnsmasq

# Build and install a patched version of OpenVPN.
# This is needed because the OpenVPN 2.3.x still does not properly handle
# floating clients (those whose source IP address as seen by the server changes
# from time to time) which is a regular occurrence in the mobile world.
# OpenVPN 2.4 might ship with proper support out of the box. In that case, this
# kludge can be removed.
#./build_openvpn.sh

# Build and install a patched version of dnsmasq.
# This is needed because GCE does not support IPv6. We thus blackhole IPv6
# traffic from clients so that they are forced to use IPv4. However, default
# DNS servers will still resolve hostnames to IPv6 addresses causing clients to
# attempt IPv6. To avoid clients attempting IPv6, we run a patched dnsmasq DNS
# server which empties AAAA records thus causing clients to go for A records
# which provide IPv4 addresses.
#./build_dnsmasq.sh

# Set up OpenVPN server
#sudo ./setup_openvpn.sh

# Set up the MiTM daemons
sudo ./setup_mitm.sh

# Move dev mitm.conf file into /etc/nogotofail directory
sudo cp /home/michael/noseyp_setup/mitm.conf /etc/nogotofail/mitm.conf

# Restart all the relevant daemons
sudo /etc/init.d/dnsmasq start
sudo /etc/init.d/openvpn start
#sudo /etc/init.d/nogotofail-mitm stop || true
sudo /etc/init.d/nogotofail-mitm start
