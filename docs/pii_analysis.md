# PII Analysis

The PII (personally identifiable information) features in nogotofail can detect PII sent in traffic between Android mobile applications and online services.

Key features include:
- Detection of PII in encrypted (HTTPS) and unencrypted (HTTP) traffic
- Auto-collection of PII data from the client's device
- Ability to define custom PII test data (using the server's configuration file)

This functionality is designed to assist in assessing two privacy risks - the disclosure of personal information in unencrypted traffic, and the excessive disclosure of personal information to application services and third parties i.e. advertising and analytics services.

TODO: Summary reporting of PII issues showing accumulated PII sent to application services over an  application session.

## <a name="pii_detection_handlers"></a>PII Detection Handlers

There are two handlers available that inspect mobile application traffic for PII:
- **httppii** - parses unencrypted (HTTP) traffic
- **httpspii** - parses encrypted (HTTPS) traffic

The **httpspii** handler acts as a man-in-the-middle (MitM) TLS proxy, intercepting and terminating requests between the client and MitM daemon, and later handling encryption of traffic between the MitM daemon and online service.

For the **httpspii** handler to perform a man-in-the-middle attack a certificate is required that is trusted by the client. There are two options available:

**a**. (Recommended) purchasing a TLS certificate from a trusted commercial CA, or

**b**. See [create_tls_proxy_cert.md](create_tls_proxy_cert.md) for instructions on generating your own CA and trusted certificate.

### a. Specifying PII Detection Handlers

nogotofail-pii can be configured to use the PII detection handlers by adding the handler arguments in the configuration (`*.mitm`) file. An example [nogotofail.mitm] configuration file section is:
```
[nogotofail.mitm]
attacks=httpspii
data=httppii

probability=0.2
debug=True

serverssl=/etc/nogotofail/mitm_controller_cert_and_key.pem
logfile=/var/log/nogotofail/mitm.log
eventlogfile=/var/log/nogotofail/mitm.event
trafficfile=/var/log/nogotofail/mitm.traffic
```

The **httppii** handler is a "data" handler and analyses the http data stream for PII information. The **httpspii** is an "attack" handler and manipulates the TLS connection.

Note. Tampering of the TLS connection by the **httpspii** handler adds latency to requests and it is recommended that you choose an attack "probability" value which minimizes the chance of request timeouts. Trial and error is required to find a suitable probability for your setup.

### b. Specifying PII Items

nogotofail has two types of PII that are detected in mobile mobile application traffic:

1. Information manually specified in the server configuration file discussed in the [Server PII](#server_pii) section.
2. Device information collected by the client app presented in the [Client PII](#client_pii) section.

<a name="server_pii"></a>
#### Server PII

The server configuration file (*.mitm) has a section named "[nogotofail.pii]" reserved for personal information that can be specified for detection. An example [nogotofail.pii] configuration file section is:

```
[nogotofail.pii]
# PII identifiers
facebook_id=abc@facebook.com
ip_address=55.66.77.88
email = joe.blogs@gmail.com
# PII details
first_name = joe
last_name = blogs
postal_address = "1 Long Road, Towns-ville"
```

To assist assessing the impact of PII disclosure in this example two arbitrary categories of PII were specified using the comment lines "PII identifiers" and "PII details".

**PII identifiers** are identifiers that uniquely identify a device or user. Examples include phone number, Facebook user ID, email.

**PII Details** describe data about the individual that may not by themselves uniquely identify them, but could identify the individual if combined with other data. Examples include first name, last name, postal address.

<a name="client_pii"></a>
#### Client PII

A number of PII items are automatically collected by the client from the device. The PII items the client collects are:

| Reserved PII | Description |
|--------------|---|
| android_id | The Android ID used by the device  |
| imei | The devices IMEI number (for SIM devices only) |
| mac_address | The devices MAC address  |
| google_ad_id | The Google Advertising ID currently assigned to the device  |
| ip_address | The devices IP address  |

Note. These PII labels are reserved and cannot be used in the server configuration file.

In terms of the arbitrary PII categories discussed earlier client PII information is typically considered to be **PII identifiers** as they uniquely identify a individual user of device.
