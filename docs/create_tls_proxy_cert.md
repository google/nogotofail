# Creating a Certificate to performing MitM TLS Proxying

nogotofail-pii can be configured to operate as a man-in-the-middle (MitM) TLS proxy and inspect encrypted (HTTPS) traffic for PII. The method described here is using a self-signed certificate and requires two certificate chain files (PEM format) to be created:

- **ca-chain-cleartext.key.cert.pem** certificate chain file contains the two certificate public key files (root and intermediate) and the intermediate certificate private key (the private key is unencrypted).
- **ca-chain.cert.pem** certificate chain file contains the two certificate public key files (for the root and intermediate certificates).

The recommended procedure below and is based on the method used here: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html

## 1. Setting up the Certificate Authority

###  a. Preparation

Create a folder to store the Certificate Authority (CA) files.

``` mkdir /root/ca ```

Text files index.txt and serial are setup to act as a kind of flat file database to keep track of signed certificates.
```
cd /root/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```
An OpenSSL configuration file openssl.cnf needs to be created for the CA. The format used is based on the following instructions: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html#prepare-the-configuration-file

### b. Creating the root key

The root key is encrypted using AES 256-bit encryption and a strong password should be used.
```
cd /root/ca
openssl genrsa -aes256 -out private/ca.key.pem 4096
```
Enter pass phrase for ca.key.pem: secretpassword
Verifying - Enter pass phrase for ca.key.pem: secretpassword

```chmod 400 private/ca.key.pem```

### c. Create the root certificate

The root certficate (ca.cert.pem) is created using the root key (ca.key.pem). The expiry date of the root certificate was set to approx 20 years (7300) days.
```
cd /root/ca
openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem

Enter pass phrase for ca.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.

Country Name (2 letter code) [XX]:AU
State or Province Name []:Australia
Locality Name []:
Organization Name []:PII MitM Ltd
Organizational Unit Name []:PII MitM Ltd Certificate Authority
Common Name []:pii.mitm.ca
Email Address []:

chmod 444 certs/ca.cert.pem
```
The root certificate should be verified using the instructions at: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html#verify-the-root-certificate

## 2. Create the TLS man-in-the-middle certificate key pair

A new certificate will be created to perform the TLS man-in-the-middle (MitM) inspection between the mobile device and server. The certificate keys will be generated from the root CA.

### a. Preparation

The new certificate files will be stored in a different directory. The suggested folder name is tlsmitm and should be created under the CA folder:

```mkdir /root/ca/tlsmitm```

Create the folders needed for this certificate using:
```
cd /root/ca/tlsmitm
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```
Add a crlnumber file to the intermediate CA directory tree to keep track of certificate revocation lists.

```echo 1000 > /root/ca/intermediate/crlnumber```

Copy the intermediate CA configuration file to /root/ca/mitm/openssl.cnf. The following five options need to be changed for this certificate:
```
[ CA_default ]
dir             = /root/ca/tlsmitm
private_key     = $dir/private/tlsmitm.key.pem
certificate     = $dir/certs/tlsmitm.cert.pem
crl             = $dir/crl/tlsmitm.crl.pem
policy          = policy_loose
```

### b. Create the certificate key

Create the tls mitm key tls.pii.mitm.ca. The intermediate key is encrypted using AES 256-bit encryption and a strong password.
```
cd /root/ca
openssl genrsa -aes256 -out tlsmitm/private/tlsmitm.key.pem 4096

Enter pass phrase for tlsmitm.key.pem: secretpassword
Verifying - Enter pass phrase for tlsmitm.key.pem: secretpassword

chmod 400 tlsmitm/private/tlsmitm.key.pem
```

### c. Create the TLS MitM certificate

The TLS MitM key is used to create a certificate signing request (CSR). The details should generally match the root CA, except the Common Name which must be different.
```
cd /root/ca
openssl req -config tlsmitm/openssl.cnf -new -sha256 -key tlsmitm/private/tlsmitm.key.pem -out tlsmitm/csr/tlsmitm.csr.pem

Enter pass phrase for tlsmitm.key.pem: secretpassword
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:AU
State or Province Name []:Australia
Locality Name []:
Organization Name []:PII MitM Ltd
Organizational Unit Name []:PII MitM Ltd Certificate Authority
Common Name []:tls.pii.mitm.ca
Email Address []:
```
To create the TLS MitM certificate, use the root CA with the v3_intermediate_ca extension to sign the intermediate CSR.
```
cd /root/ca
openssl ca -config openssl.cnf -extensions v3_intermediate_ca  -days 3650 -notext -md sha256 -in tlsmitm/csr/tlsmitm.csr.pem -out tlsmitm/certs/tlsmitm.cert.pem

Enter pass phrase for ca.key.pem: secretpassword
Sign the certificate? [y/n]: y

chmod 444 tlsmitm/certs/tlsmitm.cert.pem
```
To verify the details of this certificate are correct use the instructions at: https://jamielinux.com/docs/openssl-certificate-authority/create-the-intermediate-pair.html#verify-the-intermediate-certificate

## 3. Setting up the TLS MitM certificates

### a. Creating the certificate chain file

To create the certificate chain file ca-chain.cert.pem containing the two certificate public key files (root and TLS MitM) the two files are concatinated:
```
cat tlsmitm/certs/tlsmitm.cert.pem certs/ca.cert.pem > tlsmitm/certs/ca-chain.cert.pem
chmod 444 tlsmitm/certs/ca-chain.cert.pem
```

### b. Creating the certificate chain file with TLS MitM private key

Firstly, an unencrypted version of the TLS MitM private key needs to be created by removing the passphrase:
```
openssl rsa -in tlsmitm/private/tlsmitm.key.pem -out tlsmitm/private/tlsmitm.unencrypted.key.pem
```
Note. You will prompted to enter the passphrase.

To create the certificate chain file ca-chain-cleartext.key.cert.pem containing the two certificate public key files (root and TLS MitM) and the intermediate certificate private key (private key unencrypted), the private key and certificate chain file (form part a.) need to be concatinated:
```
cat tlsmitm/private/tlsmitm.unencrypted.key.pem tlsmitm/certs/ca-chain.cert.pem > tlsmitm/certs/ca-chain-cleartext.cert.pem
chmod 444 tlsmitm/certs/ca-chain-cleartext.cert.pem
```

### c. Installing the TLS MitM certificates

The two PEM files need to be installed before TLS MitM functionality can be enabled.

The file containing the two public keys ca-chain.cert.pem needs to be installed in the Android device's certificate key store (under the Settings > Security > Trusted Credentials option).

The file containing the two public keys and private key ca-chain-cleartext.cert.pem must be copied onto the server in the /opt/nogotofail folder.
