#!/bin/sh

set -e

DNSMASQ_VERSION="2.72"

# Download dnsmasq and verify its signature
wget http://www.thekelleys.org.uk/dnsmasq/dnsmasq-$DNSMASQ_VERSION.tar.gz
wget http://www.thekelleys.org.uk/dnsmasq/dnsmasq-$DNSMASQ_VERSION.tar.gz.asc
rm -f tmp.keyring*
gpg --no-default-keyring --keyring ./tmp.keyring --import dnsmasq-pgp-key.asc
gpg --no-default-keyring --keyring ./tmp.keyring --verify dnsmasq-$DNSMASQ_VERSION.tar.gz.asc
rm -f tmp.keyring*

# Unpack, patch, build, and install.
tar zxvf dnsmasq-$DNSMASQ_VERSION.tar.gz
cd dnsmasq-$DNSMASQ_VERSION
patch -p1 < ../dnsmasq-empty-AAAA-replies.patch
make PREFIX=/usr
sudo make install PREFIX=/usr
cd -
