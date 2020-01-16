# Getting Started
## Files you’ll need to provide


Before running nogotofail there are some files you’ll need to create or provide.

### MiTM Server certificate


The connection between clients and the MiTM is protected by a self-signed
certificate. When the client first connects the user will be prompted with the
fingerprint and asked if the server should be trusted.


For example the OpenSSL command to generate such a certificate is:

    $ openssl req -x509 -newkey rsa:2048 -sha256 -subj "/CN=mitm.nogotofail/" -nodes -keyout server.crt -out server.crt

### Invalid Hostname Certificate

The Invalid hostname attack attempts a MiTM by presenting a trusted certificate
for another domain name. For example a trusted certificate for evil.com being
presented for a connection to example.com. If the application does not do
hostname verification correctly, it will incorrectly trust the MiTM. This has
historically been one of the common SSL issues besides not checking chain of
trust of SSL certificates.  To test for this issue you will need to provide a
trusted certificate chain for an arbitrary domain. You have two options for how
to do this, depending on cost and control of the test device.

1. Purchase a certificate for a domain you own from a trusted CA. This will cost
you $50-70 but is the most flexible as it requires no modification of test
devices. To prevent false positives this should be for a domain or subdomain
that no one will ever connect to.

2. If you cannot purchase a certificate the other option is to create a CA and
add it to your test devices as a trusted CA. At that point you can issue a
certificate and use that as the invalid hostname certificate.

Once you have a trusted certificate chain, put the chain and the private key in
the file “trusted-cert.pem” in nogotofail.mitm’s working directory. Do not
password protect the private key in this file.

To verify the chain is correct
    $ openssl verify -CApath /etc/ssl/certs/ -untrusted trusted-cert.pem trusted-cert.pem
You should see OK as the output.

### ImageReplace Image

If you decide to use the image replacement data attack you’ll need to provide an image to
replace with in the form of replace.png in nogotofail.mitm’s working directory.
We recommend something noticeable that scales well.

## Example Walkthrough


Here is a quick walkthrough of running and testing the MiTM locally.


First, we’ll start the MiTM running as a SOCKS5 proxy.

    $ python -m nogotofail.mitm --mode socks --port 8080 --serverssl server.crt

````
--mode socks - run as a SOCKS5 proxy
--port 8080 - listen on 8080
--serverssl servert.crt- The certificate we generated above. This will be used for the client connections.
````

Now you can connect through the socks proxy using a tool like tproxy or
proxychains. For this example we’ll proxy chains with the config:

    $ cat ./proxychains.conf
    strict_chain
    tcp_read_time_out 15000
    tcp_connect_time_out 8000
    [ProxyList]
    socks5 127.0.0.1 8080

Now let’s run wget using proxychains.

    $ proxychains wget http://example.com -4 -O example

Note: proxychains doesn’t support IPv6 so force IPv4 with -4.


The nogotofail.mitm output should now show:

    2014-10-22 13:06:48,948 [INFO] Starting...
    2014-10-22 13:07:53,711 [INFO] [127.0.0.1:42974<=>93.184.216.119:80 logging](Unknown) Selected for connection
    2014-10-22 13:07:53,714 [INFO] [127.0.0.1:42974<=>93.184.216.119:80 logging](Unknown) Connection established
    2014-10-22 13:07:53,716 [ERROR] [127.0.0.1:42974<=>93.184.216.119:80 httpdetection](Unknown) HTTP request GET example.com/
    2014-10-22 13:07:53,722 [INFO] [127.0.0.1:42974<=>93.184.216.119:80 logging](Unknown) Connection closed


The format for the connection logs is:

    TIME [LEVEL] [SRC<=>DST HANDLER](CLIENTINFO) MESSAGE


We can see that the connection starts using the basic logging connection handler
and then on line 4 the httpdetection data handler detected an HTTP request, and
then connection closed.


Now, let’s try again but this time with the Linux nogotofail client.

    $ python -m nogotofail.clients.linux.pyblame -v localhost 8443

You should see a prompt asking if you trust the certificate the MiTM is
presenting, check that the fingerprint matches that of your certificate.


Now, if we rerun the same wget command and look at the logs:

    2014-10-22 13:17:16,794 [INFO] AppBlame new client from 127.0.0.1
    2014-10-22 13:17:18,874 [INFO] [127.0.0.1:43525<=>93.184.216.119:80 logging](client=Linux 3.13.0-37-generic application="wget example.com" version="0") Selected for connection
    2014-10-22 13:17:18,877 [INFO] [127.0.0.1:43525<=>93.184.216.119:80 logging](client=Linux 3.13.0-37-generic application="wget example.com" version="0") Connection established
    2014-10-22 13:17:18,878 [ERROR] [127.0.0.1:43525<=>93.184.216.119:80 httpdetection](client=Linux 3.13.0-37-generic application="wget example.com" version="0") HTTP request GET example.com/
    2014-10-22 13:17:18,885 [INFO] [127.0.0.1:43525<=>93.184.216.119:80 logging](client=Linux 3.13.0-37-generic application="wget example.com" version="0") Connection closed


There is a lot more data here this time, so let’s break down the new
information. First there is the client information which tells us extra
information about the machine being tested, and second we see the application being
run is “wget example.com”. This socks proxy example is basic but once you are
running with multiple devices and all their traffic it is important to be able
to narrow down exactly who each connection belongs to.


Now let’s look at a basic SSL MiTM attack, using wget.


First, let’s re run the client and tell the MiTM to always run a simple self signed certificate attack:

    $ python -m nogotofail.clients.linux.pyblame -A selfsigned -D httpdetection -p 1 -v localhost 8443

````
-A - set the attacks to run, in this case we are just using the self signed certificate attack
-D - data handlers to run
-p - probability of attack, setting this to 1 means every TLS/SSL connection will be attacked.
````

And now let’s run wget with cert checking disabled to simulate a vulnerability

    $ proxychains wget https://google.com --no-check-certificate -4

The logs should now show:

    2014-10-22 13:45:19,852 [INFO] [127.0.0.1:44754<=>74.125.239.114:443 logging](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") Selected for connection
    2014-10-22 13:45:19,854 [INFO] [127.0.0.1:44754<=>74.125.239.114:443 logging](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") Connection established
    2014-10-22 13:45:19,856 [INFO] [127.0.0.1:44754<=>74.125.239.114:443 logging](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") Handler being removed
    2014-10-22 13:45:19,856 [INFO] [127.0.0.1:44754<=>74.125.239.114:443 selfsigned](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") Selected for connection
    2014-10-22 13:45:20,059 [INFO] [127.0.0.1:44754<=>74.125.239.114:443 selfsigned](client=Linux 3.13.0-37-generic  application="wget https://google.com" version="0") SSL connection established
    2014-10-22 13:45:20,059 [CRITICAL] [127.0.0.1:44754<=>74.125.239.114:443 selfsigned](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") MITM Success! Cert file: /tmp/.cert_-4408897662695739272.pem
    2014-10-22 13:45:20,061 [ERROR] [127.0.0.1:44754<=>74.125.239.114:443 httpdetection](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") HTTP request GET www.google.com/
    2014-10-22 13:45:20,144 [INFO] [127.0.0.1:44754<=>74.125.239.114:443 selfsigned](client=Linux 3.13.0-37-generic application="wget https://google.com" version="0") Connection closed


There are a lot more events here, lines 1-2 are the same initial connection as before but the rest are new.  
1. The logging handler is getting removed to be replaced by another. This is
because an SSL handshake was detected and we decided to attack.  
2. the selfsigned connection handler is added, it will now try and do a man in 
the middle attack  
3. The SSL handshake was completed. This isn’t a guarantee that the attack 
succeeded as some applications will complete the handshake but refuse to use the
bad socket  
4. MiTM success! This happens as soon as the man in the middled connection is 
used to transfer application data. We also log the certificate we used for the
attack for later analysis.  
5. Now that we are a MiTM we see the HTTP get request  
6. The connection closes


### Getting on path


Now that you’ve set up nogotofail and seen how it runs the next step is to put
it in a setup where you can use it on path. Nogotofail was designed to work
anywhere on path, so you have a lot of flexibility in deployment. Here are a few ways
we have deployed nogotofail in our testing. Setting up these deployments is beyond the scope
of this document but there is plenty of open documentation out there for how to set up machines
in these configurations.

1. Run nogotofail on an actual router. This has the benefit of being completely
transparent to the clients as they simply connect through router as usual.
Unfortunately setting up a router can be somewhat painful and router hardware
tends to be a bit limited. nogotofail.mitm’s only dependency is pyOpenSSL >=0.13,
so it isn’t hard to configure a router that can run nogotofail.

2. Run nogotofail on a Linux machine with two network interfaces. This is transparent like the router
case but easier to set up. You will want one interface connected to the Internet and the other to
the client. You will need to run dnsmasq to handle DNS and DHCP for the client. If your machine supports
it you can use WiFi to connect the clients, but that requires your WiFi driver to support AP mode.

3. Another option which is easier to set up but less transparent is to run a
nogotofail.mitm on a VPN server, and have the clients connect over the VPN. This
is less transparent to the client but usually easier to set up. We recommend
OpenVPN as there is lots of documentation for how to set up an OpenVPN server.
Our main setup has been OpenVPN running on a Google Compute Engine instance. See instructions in
[gce/readme.md](gce/readme.md).

#### Testing Android
For testing Android devices we have included our [Android client](/nogotofail/clients/android) ready
to be imported into Eclipse. You will have to build the app and install it on your test device.

For testing you can use the access point nogotofail setups or on  devices >=JB you can use
the OpenVPN setup and a third party VPN application to route your traffic.


##### Getting on path on a Linux machine
On a Linux machine with the following example topology:


    -------------            ----------            ----------
    |test device|--------eth1|MiTM box|eth0--------|internet|
    -------------            ----------            ----------


First enable IP forwarding

    $ echo 1 > /proc/sys/net/ipv4/ip_forward

Next set up eth1 with an IP address

    $ ifconfig eth1 10.0.0.1

Then set up NAT on the device

    $ iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

Finally run dnsmasq for DNS and DHCP:

    $ dnsmasq eth1


Now traffic will be flowing through the MiTM box from the test device to the
Internet.


### Now you’re on path


By default clients connect to the MiTM using hostname mitm.nogotofail
port 8443. You can change your clients’ configuration or use dnsmasq(or
similar) to resolve mitm.nogotofail to the machine running
nogotofail.mitm. To do this add the line:

    <your ip address here> mitm.nogotofail

to /etc/hosts

Now you’re ready to run notogofail. If you’re running it as a service you might
want to use the config file instead of passing arguments. You can see an example
in [example.conf](example.conf), and run it with `python -m nogotofail.mitm -c <config file>`.
If you’re running in an iptables mode you’ll also need to run nogotofail.mitm as
root so it can set up the routing rules to intercept traffic.

#### Useful arguments



nogotofail.mitm has a lot of configuration options, here are some of the
important ones you’ll want to tweak.

    -p/--probability: Set the probability of attack an TLS/SSL connection. See the
    “Why Probability” section for details on probability.
    -A/--Attacks: Set the default connection handlers to run when TLS/SSL is
    detected. See --help for the list of all attacks and docs/mitm for details about
    handlers
    -D/--Data: Set the default data handlers to run. See  --help for the list and
    docs/mitm for details about handlers
    --servercert: The SSL cert to use for client connections.
    -6/--ipv6: Also attack IPv6 traffic. This should work in socks and tproxy modes
    without issue, redirect mode requires very recent iptables and kernel support.
    Note that proxychains doesn’t support IPv6 connections.
    --mode <mode>: Sets the mode of traffic interception.
            tproxy: The default. This sets up iptables tproxy rules and IP routes to
            transparently redirect all traffic to the MiTM.
            redirect: This uses iptables NAT rules to transparently redirect all
            traffic to the MiTM. This has poorer IPv6 support than tproxy but has
            been better tested in nogotofail.
            socks: This mode runs a SOCKS5 proxy on --port (default 8080). Unlike
            the iptables modes this mode doesn’t transparently capture all traffic,
            but it is very useful for local testing and testing things which support
            proxy configs.

 You can see all the options by running `python -m nogotofail.mitm --help`.

##### Logging


Additionally, you will probably want to log to files in addition to stdout.

    -l <file>: This is a copy of the verbose log output
    -e <file>: File for machine parseable event logs.
    -t <file>: File for machine parseable traffic logs.




The event and traffic log allow you pipeline events nogotofail for later analysis or display.
The format for the data in the event and traffic files are:
````
event_json\n
event_json\n
````
…
Parsing an event in python is simply:
    > json.loads(file.readline())


The event contains all of the connection information, the handler logging the
event, and any additional information. The event log contains events for attack
attempts and successes. The traffic log contains connection established/closed
events as well as the raw traffic. You can see the exact properties in
nogotofail/mitm/event/connection.py


For the raw traffic each event contains the source (either client or server), if
it was injected by the mitm as opposed to sent by an endpoint, and the data
base64 encoded.


Note that due to how man in the middle attacks are established the traffic logs
won’t include SSL handshakes done by nogotofail and will show the decrypted
traffic if a man in the middle is successful.
