#!/bin/sh

set -e

OPENVPN_VERSION="2.4.2"

# Download OpenVPN and verify the signature on the archive
rm -f openvpn-$OPENVPN_VERSION.tar.gz*
wget https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz
wget https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz.asc
rm -f tmp.keyring*
gpg --no-default-keyring --keyring ./tmp.keyring --import openvpn-pgp-key.asc
gpg --no-default-keyring --keyring ./tmp.keyring --verify openvpn-$OPENVPN_VERSION.tar.gz.asc
rm -f tmp.keyring*

# Unpack, build, and install.
rm -Rf openvpn-$OPENVPN_VERSION
tar zxvf openvpn-$OPENVPN_VERSION.tar.gz
cd openvpn-$OPENVPN_VERSION
./configure --prefix=/usr
make
sudo make install
cd -
