#!/bin/sh

set -e

INSTALL_DIR=/opt/nogotofail
CONFIG_DIR=/etc/nogotofail
LOG_DIR=/var/log/nogotofail

# Install the relevant source subtree into $INSTALL_DIR
mkdir -p $INSTALL_DIR $CONFIG_DIR
cp -a ../../nogotofail $INSTALL_DIR/
chown -R root:root $INSTALL_DIR
chmod -R go-w $INSTALL_DIR

# Create configs in $CONFIG_DIF
cp mitm.conf $CONFIG_DIR && \
openssl req -x509 -newkey rsa:2048 -sha256 -keyout $CONFIG_DIR/mitm_controller_key.pem -out $CONFIG_DIR/mitm_controller_cert.pem -days 365 -nodes -subj '/CN=mitm.nogotofail'
cat $CONFIG_DIR/mitm_controller_cert.pem $CONFIG_DIR/mitm_controller_key.pem > $CONFIG_DIR/mitm_controller_cert_and_key.pem
rm $CONFIG_DIR/mitm_controller_key.pem $CONFIG_DIR/mitm_controller_cert.pem
chmod 600 $CONFIG_DIR/mitm_controller_cert_and_key.pem
chown -R root:root $CONFIG_DIR
chmod -R go-w $CONFIG_DIR

# Add /etc/init.d/nogotofail-mitm daemon start/stop script
cp nogotofail-mitm /etc/init.d/ && \
chown root:root /etc/init.d/nogotofail-mitm && \
chmod 750 /etc/init.d/nogotofail-mitm && \

# Create log directory
mkdir -p $LOG_DIR

# Add mitm.nogotofail. to /etc/hosts
if [ "$(grep mitm.nogotofail /etc/hosts)" = "" ]; then
  echo "Adding mitm.nogotofail. to /etc/hosts..."
  /bin/echo -e "10.8.0.1\tmitm.nogotofail." >> /etc/hosts
fi

