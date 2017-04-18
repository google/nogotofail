# MiTM Details
## How MiTM intercepts traffic

Nogotofail currently supports three traffic interception modes that can be
selected using the --mode option. The tproxy and redirect modes are
transparent to the client and destination, and are for running nogotofail on-path.
Note they require the MiTM to be run as root in order to create the iptables
and routing rules to capture traffic.

### tproxy
Tproxy mode uses iptables tproxy and ip mark routing rules to route all traffic
passing through the device to nogotofail.

### redirect
Redirect mode uses iptables nat redirection to route all traffic passing
through the device to nogotofail. Redirect is the older and more tested way of
routing traffic to nogotofail but has poor IPv6 support, requiring bleeding
edge iptables and Linux kernel >= 3.7.

### socks
Socks mode has nogotofail listening as a SOCKS5 proxy. Unlike the iptables
rules this doesn’t require nogotofail to be on path or have root access, but it
does lose the transparency of those modes.

It is also useful when testing changes to nogotofail locally, as it requires minimal setup.

# Architecture Overview

## Connections
Every TCP connection is routed to a nogotofail connection which is responsible
for bridging traffic, detecting TLS/SSL traffic and sending events to handlers
which implement attacks and detection.

## Handlers
All the actual vulnerability detection is done in small event handlers. In
nogotofail there are two types of handlers, connection handlers and data
handlers. You can see all the events handlers receive and their documentation in
(nogotofail/mitm/connection/handlers/base.py)[nogotofail/mitm/connection/handlers/base.py]

### Connection Handlers
Each connection in nogotofail has only one connection handler which is
responsible for doing connection level testing on TLS/SSL. These are used for
vulnerabilities like accepting self-signed certificates or heartbleed.

### Data Handlers
Data handlers are responsible for detecting issues in traffic or modifying
traffic to test for vulnerabilities. Unlike Connection Handlers each connection
can have multiple data handlers whose outputs are chained together. These are
used for vulnerabilities like detecting auth tokens in cleartext or attempting
ssl stripping attacks.

## Life of a connection
1. When a connection is first created it selects the initial connection handler and the list of data handler.
2. Each handler’s on_select method is called.
3. Once the connection to the remote is successful each handler’s on_establish is called
4. When data is sent from the client->server it is chained through each handler’s on_request starting with the connection handler and then going through the data handlers in order.
5. When data is sent from the server->client it is chained through each handler’s on_response.
6. If a TLS/SSL Client Hello is detected by the connection the connection checks if it should MiTM’d. See ‘on TLS Client Hello’.
7. When the connection is closed each handler’s on_close is called

### On TLS/SSL Client Hello
1. When a TLS/SSL client hello is detected the connection selects a new connection handler for the TLS/SSL connection.
2. If handler.on_ssl returns False the connection will continue simply bridging traffic as before
3. Otherwise the connection to the server is wrapped with TLS/SSL and handler.on_certificate is called with the cert presented by the server to generate a certificate to present to the client
4. The TLS/SSL handshake is done with the client using the certificate/key from on_certificate
5. Once the handshake is completed the connection handler’s on_ssl_established in called. Note that this doesn’t mean the MiTM was successful as hostname verification is typically performed on most clients only after the handshake finishes.
6. The connection now operates as normal.
