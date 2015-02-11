# Supported Attacks
Each of the handlers attempts to exploit a specific TLS/SSL vulnerability.
There are two types of TLS handlers by nogotofail:
+ handlers which test for vulnerabilities allowing insecure **connections**, and
+ handlers which detect or exploit vulnerabilites affecting **data** security.

Handlers write [WARNING], [ERROR] or [CRITICAL] messages to the output log (-l) based on the severity. 

##Connection Handlers
The available data handlers are available are:
+ droptls - Drops TLS connections but lets SSLv3 connections through
+ selfsigned - Attempts to MiTM using a self-signed certificate for the requested domain.
  An output log [CRITICAL] message appears when a self-signed certificate is accepted by an app.
+ clientheartbleed - Sends a heartbleed message to the client during the SSL handshake
  An output log [CRITICAL] message appears when a Heartbleed response is received
+ anonserver - Attempts to MiTM connections that accept anonymous/unauthenticated server.
+ dropssl - Drops SSL connections
+ invalidhostname - Attempts to MiTM using a valid certificate for another domain.
  NOTE: The certificate used for testing must have the path “./trusted-cert.pem” and have a valid cert and private key.
+ earlyccs - Tests for OpenSSL early CCS vulnerability(CVE-2014-0224)
  An output log [CRITICAL] message appears when the client is vulnerable to the Early CCS attack.
+ serverkeyreplace - Tests for clients vulnerable to SSL server key substitution
  An output log [CRITICAL] message appears when the client is vulnerable to the server key substitution attack.

##Data Handlers
The available data handlers are available are:
+ imapstarttlsstrip - Suppress STARTTLS in IMAP
+ httpauthdetection - Detect authorization headers in HTTP requests
  An output log [CRITICAL] message appears when an Authorization header is found in a request.
+ imagereplace - Replace responses with Content-Type of image/* with ./replace.png
+ customrequest - Detect client specified regexs in requests
+ weaktlsversiondetection - Detect versions of the TLS/SSL protocols that are known to be weak.
  An output log [CRITICAL] message appears when:
  + SSLv3 is used without support for TLS_FALLBACK_SCSV, or i.e. the POODLE vulnerability https://www.imperialviolet.org/2014/10/14/poodle.html
  + SSLv2 is detected
  Output log [WARNING] messages occur when SSLv3 is used with TLS_FALLBACK_SCSV supported
+ insecurecipherdetection - Detect insecure cipher suites in TLS Client Hellos.
  Output log [ERROR] messages appear when one of the following conditions is detected:
  + anonymous (asymmetric encryption) ciphers, 
  + no or NULL asymmetric encryption, symmetric encryption, or 
  + no integrity algorithm (message authentication code) is specified in the cipher suite.
+ blockhttp - Block HTTP traffic
+ disablecdcpencryption - Disable Chrome Data Compression Proxy encryption
+ sslstrip - Runs sslstrip on http traffic. Detects when sslstrip'd urls are visited.
  An output log [CRITICAL] message appears when the client visits a SSLStrip'd URL.
+ httpdetection - Detects plaintext HTTP requests i.e. not using SSL/TLS.
+ xmppstarttlsstrip - Suppress STARTTLS in XMPP streams
+ rawlogger - Log raw traffic to the traffic log
+ androidwebviewjsrce - Detect Android Webview Javascript RCE
  An output log [CRITICAL] message appears when the client is found to be vulnerable to the Webview Javascript RCE exploit.
  
+ xmppauthdetection - Detect authentication credentials in XMPP traffic
  An output log [ERROR] message appears when credentials are detect in XMPP traffic.
  Output log [WARNING] messages appear when:
  + the XMPP STARTTLS feature is missing, or
  + the handler failed to strip XMPP STARTTLS
+ smtpstarttlsstrip - Suppress STARTTLS in SMTP
  An output log [CRITICAL] message appears when cleartext SMTP traffic is found after STARTTLS is stripped.
+ smtpauthdetection - Detect authentication credentials in SMTP traffic
+ imapauthdetection - Detect authentication credentials in IMAP traffic.
  An output [CRITICAL] message appears when credentials are found in cleartext IMAP traffic.
