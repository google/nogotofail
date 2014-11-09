#Nogotofail MiTM on Google Compute Engine VM instance

## Overview
In this setup, traffic from clients to be MiTM'd is routed through a Google
Compute Engine (GCE) VM instance to the Internet. Nogotofail MiTM is running
on the GCE instance and is MiTMing the traffic. Clients route their traffic
to the GCE instance via OpenVPN.

## Instructions
### Create the GCE instance
1. Go to the Google Developer Console -> Compute -> Compute Engine -> VM
   instances. Then click on New instance button. In the External IP section
   choose static IP address. Create the instance.
2. Go to Compute Engine -> Networks, click on default, create a new firewall
   rule for OpenVPN: set protocols & ports to udp:1194.
3. You should now have a GCE instance reachable on a static IP address and
   whose firewall permits OpenVPN traffic in and out.

### Set up the GCE instance
1. SCP the source tree of nogotofail into the GCE instance.
2. SSH into the GCE instance
3. cd into docs/gce of the nogotofail source tree.
4. Run ./setup.sh. This will set up an OpenVPN server, dnsmasq DNS server,
   and nogotofail MiTM daemon.
5. Optionally, to enable the invalidhostname attack where the MiTM presents
   a trusted certificate for the wrong hostname, provide the trusted
   certificate chain and the private key in /opt/nogotofail/trusted-cert.pem.
   See the Invalid Hostname Certificate section of the Getting Started guide
   [../getting_started.md](../getting_started.md).


### Set up the client(s) to be MiTM'd
1. Obtain /etc/openvpn/nogotofail.ovpn from the GCE instance.
2. Install an OpenVPN client.
3. Configure the OpenVPN client with the above nogotofail.ovpn.
4. Establish the VPN connection.
5. Check that Internet access is working.
6. Check that the IP address as seen by Internet servers is the external IP
   address of the GCE instance. For example, load http://ip6.me in the web
   browser.
7. On the GCE instance, check that the traffic from this client is seen
   by the MiTM by looking at / tailing /var/log/nogotofail/mitm.log.


## Architecture

IP traffic from clients is routed via an OpenVPN tunnel to the GCE instance
and then onwards to the Internet. Nogotofail MiTM daemon is on-path by running
inside the GCE instance and getting traffic redirected to it by iptables.

The GCE instance thus hosts:
* OpenVPN server,
* dnsmasq DNS server,
* nogotofail MiTM daemon.

GCE does not support IPv6 which complicates matters because most clients support
IPv6 and more and more servers on the Internet are reachable via IPv6. As a
workaround, OpenVPN configuration tells clients to blackhole IPv6 traffic by
routing it to a non-existent address. Moreover, because clients can resolve
hostnames to IPv6 addresses using IPv4 requests to DNS, the GCE instance's DNS
server is modified to empty all AAAA responses. This makes the clients assume
that the resolved host is not reachable via IPv6. This in turn makes the clients
use only IPv4 which is routed just fine through the GCE.

