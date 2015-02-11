

Connection Handlers
Each of the handlers detects a specific TLS/SSL vulnerability. The available data handlers are available are:
•	droptls - Drops TLS connections but lets SSLv3 connections through
•	selfsigned - Attempts to MiTM using a self-signed certificate for the requested domain.
NOTE. Requires a self-signed certificate to be generated
•	clientheartbleed - Sends a heartbleed message to the client during the SSL handshake
•	anonserver - Attempts to MiTM connections that accept anonymous/unauthenticated server.
•	dropssl - Drops SSL connections
•	invalidhostname - Attempts to MiTM using a valid certificate for another domain.
NOTE: The certificate used for testing must have the path “./trusted-cert.pem” and have a valid cert and private key.
•	earlyccs - Tests for OpenSSL early CCS vulnerability(CVE-2014-0224)
Data Handlers
The available data handlers are available are:
•	imapstarttlsstrip - Suppress STARTTLS in IMAP
•	httpauthdetection - Detect authorization headers in HTTP requests
•	imagereplace - Replace responses with Content-Type of image/* with ./replace.png
•	customrequest - Detect client specified regexs in requests
•	weaktlsversiondetection - Detect versions of the TLS/SSL protocols that are known to be weak.
Output log (-l) [ERROR] messages occur when the following conditions are detected:
  o	SSLv3 without support for TLS_FALLBACK_SCSV i.e. the POODLE vulnerability https://www.imperialviolet.org/2014/10/14/poodle.html
  o	SSLv2
Output log [WARNING] messages occur when:
  o	SSLv3 with TLS_FALLBACK_SCSV supported

•	insecurecipherdetection - Detect insecure cipher suites in TLS Client Hellos.
Output log (-l) [ERROR] messages occur when the following conditions are detected:
  o	Anonymous (asymmetric encryption) ciphers, 
  o	No or NULL asymmetric encryption, symmetric encryption, or 
  o	no integrity algorithm (message authentication code) is specified in the cipher suite.
•	blockhttp - Block HTTP traffic
•	disablecdcpencryption - Disable Chrome Data Compression Proxy encryption
•	sslstrip - Runs sslstrip on http traffic. Detects when sslstrip'd urls are visited.
•	httpdetection - Detects plaintext HTTP requests i.e. not using SSL/TLS.
•	xmppstarttlsstrip - Suppress STARTTLS in XMPP streams
•	rawlogger - Log raw traffic to the traffic log
•	androidwebviewjsrce - Detect Android Webview Javascript RCE
•	xmppauthdetection - Detect authentication credentials in XMPP traffic
•	smtpstarttlsstrip - Suppress STARTTLS in SMTP
•	smtpauthdetection - Detect authentication credentials in SMTP traffic
•	imapauthdetection - Detect authentication credentials in IMAP traffic.
