# Supported Attacks
Each of the handlers attempts to exploit a specific TLS/SSL vulnerability.
There are two types of TLS handlers by nogotofail:
+ handlers which test for vulnerabilities allowing insecure **connections**, and
+ handlers which detect or exploit vulnerabilites affecting **data** security.

Handlers write [WARNING], [ERROR] or [CRITICAL] security issues to the output log (-l) based on the their severity. 

##Connection Handlers
The available data handlers are available are:
+ droptls - Drops TLS connections but lets SSLv3 connections through
+ selfsigned - Attempts to MiTM using a self-signed certificate for the requested domain.
  Output log messages generated: 
  + [CRITICAL] Client accepts self-signed certificate and creates connection
+ clientheartbleed - Sends a heartbleed message to the client during the SSL handshake.
  Output log messages generated:
  + [CRITICAL] Client returns a Heartbleed response
+ anonserver - Attempts to MiTM connections that accept anonymous/unauthenticated server.
  Output log messages generated:
  + [CRITICAL] Client accepts server certificate certificate and creates connection
+ dropssl - Drops SSL connections
+ invalidhostname - Attempts to MiTM using a valid certificate for another domain.
  NOTE: The certificate used for testing must have the path “./trusted-cert.pem” and have a valid cert and private key.
+ earlyccs - Tests for OpenSSL early CCS vulnerability(CVE-2014-0224)
  Output log messages generated:
  + [CRITICAL] when the client is vulnerable to the Early CCS attack
+ serverkeyreplace - Tests for clients vulnerable to SSL server key substitution.
  Output log messages generated:
  + [CRITICAL] Client is vulnerable to the server key substitution attack

##Data Handlers
The available data handlers are available are:
+ imapstarttlsstrip - Suppress STARTTLS in IMAP.
  Output log messages generated:
  + [CRITICAL] Cleartext traffic appears after STARTTLS is stripped
+ httpauthdetection - Detect authorization headers in HTTP requests.
  Output log messages generated:
  + [CRITICAL] Authorization header in request from client
+ imagereplace - Replace responses with Content-Type of image/* with ./replace.png
+ customrequest - Detect client specified regexs in requests
+ weaktlsversiondetection - Detect versions of the TLS/SSL protocols that are known to be weak.
  Output log messages generated:
  + [CRITICAL] SSLv3 is used without support for TLS_FALLBACK_SCSV, or i.e. the POODLE vulnerability https://www.imperialviolet.org/2014/10/14/poodle.html
  + [ERROR] Client enabled SSLv2 protocol
  + [ERROR] Client enabled SSLv3 protocol without TLS_FALLBACK_SCSV
  + [WARNING] Client enabled SSLv3 protocol with TLS_FALLBACK_SCSV
+ insecurecipherdetection - Detect insecure cipher suites in TLS Client Hellos.
  Output log messages generated:
  + [ERROR] Use of anonymous (asymmetric encryption) in the cipher suite 
  + [ERROR] NULL asymmetric encryption or symmetric encryption in the cipher suite 
  + [ERROR] no integrity algorithm (message authentication code) is specified in the cipher suite.
+ blockhttp - Block HTTP traffic
+ disablecdcpencryption - Disable Chrome Data Compression Proxy encryption
+ sslstrip - Runs sslstrip on http traffic. Detects when sslstrip'd urls are visited.
  Output log messages generated:
  + [CRITICAL] Client detected visiting an SSLStrip'd URL
+ httpdetection - Detects plaintext HTTP requests i.e. not using SSL/TLS.
  Output log messages generated:
  + [ERROR] Client HTTP request detected 
+ xmppstarttlsstrip - Suppress STARTTLS in XMPP streams
  Output log messages generated:
  + [CRITICAL] Cleartext traffic is detected after stripped STARTTLS
  + [WARNING]  XMPP STARTTLS feature missing
  + [WARNING]  Failed to strip XMPP STARTTLS
+ rawlogger - Log raw traffic to the traffic log
+ androidwebviewjsrce - Detect Android Webview Javascript RCE.
  Output log messages generated:
  + [CRITICAL] Client is vulnerable to the Webview Javascript RCE exploit
+ xmppauthdetection - Detect authentication credentials in XMPP traffic.
  Output log messages generated:
  + [CRITICAL] Authentication credentials detected in XMPP traffic
  + [ERROR]    Credentials are detected in XMPP traffic
  + [WARNING]  XMPP STARTTLS feature is missing
  + [WARNING]  Handler failed to strip XMPP STARTTLS
+ smtpstarttlsstrip - Suppress STARTTLS in SMTP.
  Output log messages generated:
  + [CRITICAL] Cleartext SMTP traffic detected after STARTTLS is stripped
+ smtpauthdetection - Detect authentication credentials in SMTP traffic.
  + [CRITICAL] Authentication credentials detected in SMTP traffic
+ imapauthdetection - Detect authentication credentials in IMAP traffic.
  Output log messages generated:
  + [CRITICAL] Credentials are detected in cleartext IMAP traffic.
