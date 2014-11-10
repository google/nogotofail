#!/bin/sh

set -e

SRC_DIR="$(pwd)"
CONFIG_DIR=/etc/openvpn

# Set up $CONFIG_DIR
mkdir -p $CONFIG_DIR
chown root:root $CONFIG_DIR
chmod 755 $CONFIG_DIR

# Generate CA, server, and client public key pairs and certificates.
# OpenVPN doesn't like working without a CA...
echo "Generating CA public key pair and certificate..."
openssl req -x509 -newkey rsa:2048 -sha256 -keyout $CONFIG_DIR/ca_key.pem -out $CONFIG_DIR/ca_cert.pem -nodes -days 730 -subj '/CN=ca.vpn.nogotofail'
chmod 600 $CONFIG_DIR/ca_key.pem

echo "Generating server public key pair and certificate..."
openssl genrsa -out $CONFIG_DIR/server_key.pem 2048
openssl req -new -key $CONFIG_DIR/server_key.pem -out $CONFIG_DIR/server_csr.pem -subj '/CN=server.vpn.nogotofail'
chmod 600 $CONFIG_DIR/server_key.pem
openssl x509 -req -in $CONFIG_DIR/server_csr.pem -CA $CONFIG_DIR/ca_cert.pem -CAkey $CONFIG_DIR/ca_key.pem -CAcreateserial -out $CONFIG_DIR/server_cert.pem -sha256 -days 365
rm $CONFIG_DIR/server_csr.pem

echo "Generating client public key pair and certificate..."
openssl genrsa -out $CONFIG_DIR/client_key.pem 2048
openssl req -new -key $CONFIG_DIR/client_key.pem -out $CONFIG_DIR/client_csr.pem -subj '/CN=client.vpn.nogotofail'
openssl x509 -req -in $CONFIG_DIR/client_csr.pem -CA $CONFIG_DIR/ca_cert.pem -CAkey $CONFIG_DIR/ca_key.pem -CAcreateserial -out $CONFIG_DIR/client_cert.pem -sha256 -days 365
rm $CONFIG_DIR/client_csr.pem

openssl dhparam 2048 > $CONFIG_DIR/dhparam2048.pem

cp "$SRC_DIR/openvpn.conf" $CONFIG_DIR/

# Determine external IP address of this host.
echo -n "Determining external IP address of this host... "
HOSTNAME=$(curl -f ifconfig.me 2>/dev/null)
echo "Detected: $HOSTNAME"

# Generate OVPN config file to be used by clients to connect to this VPN server
echo "Generating client OVPN config file..."
CLIENT_CONFIG=$CONFIG_DIR/nogotofail.ovpn
echo "setenv FRIENDLY_NAME \"nogotofail@$HOSTNAME\"" > $CLIENT_CONFIG
echo "# OVPN_ACCESS_SERVER_FRIENDLY_NAME=nogotofail@$HOSTNAME" >> $CLIENT_CONFIG
echo "remote $HOSTNAME 1194" >> $CLIENT_CONFIG
cat "$SRC_DIR/nogotofail.ovpn.template" >> $CLIENT_CONFIG
echo >> $CLIENT_CONFIG
echo "<ca>" >> $CLIENT_CONFIG
cat $CONFIG_DIR/ca_cert.pem >> $CLIENT_CONFIG
echo "</ca>" >> $CLIENT_CONFIG
echo "<cert>" >> $CLIENT_CONFIG
cat $CONFIG_DIR/client_cert.pem >> $CLIENT_CONFIG
echo "</cert>" >> $CLIENT_CONFIG
echo "<key>" >> $CLIENT_CONFIG
cat $CONFIG_DIR/client_key.pem >> $CLIENT_CONFIG
echo "</key>" >> $CLIENT_CONFIG

# Patch /etc/init.d/openvpn to modify routing and iptables
if [ "$(grep iptables /etc/init.d/openvpn)" = "" ]; then
  echo "Patching /etc/init.d/openvpn..."
  patch -d /etc/init.d -p1 < "$SRC_DIR/openvpn-start-stop.patch"
fi

