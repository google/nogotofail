#!/bin/sh

set -e

OPENVPN_VERSION="2.3.5"

# Download OpenVPN and verify the signature on the archive
rm -f openvpn-$OPENVPN_VERSION.tar.gz*
wget http://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz
wget http://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VERSION.tar.gz.asc
rm -f tmp.keyring*
gpg --no-default-keyring --keyring ./tmp.keyring --import openvpn-pgp-key.asc
gpg --no-default-keyring --keyring ./tmp.keyring --verify openvpn-$OPENVPN_VERSION.tar.gz.asc
rm -f tmp.keyring*

# Download the patch for improved handling of floating clients
rm -f tlsfloat.2.patch
wget https://community.openvpn.net/openvpn/raw-attachment/ticket/49/tlsfloat.2.patch

# Unpack, patch, build, and install.
rm -Rf openvpn-$OPENVPN_VERSION
tar zxvf openvpn-$OPENVPN_VERSION.tar.gz
cd openvpn-$OPENVPN_VERSION
patch -p1 < ../tlsfloat.2.patch
./configure
make
sudo make install
cd -
