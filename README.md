#nogotofail


Nogotofail is a network security testing tool designed to help developers and
security researchers spot and fix weak TLS/SSL connections and sensitive
cleartext traffic on devices and applications in a flexible, scalable, powerful way.
It includes testing for common SSL certificate verification issues, HTTPS and TLS/SSL
library bugs, SSL and STARTTLS stripping issues, cleartext issues, and more.

##Design
Nogotofail is composed of an on-path network MiTM and optional clients for the devices being tested.
See [docs/design.md](docs/design.md) for the overview and design goals of nogotofail.

##Dependencies
Nogotofail depends only on Python 2.7 and pyOpenSSL>=0.13. The MiTM is designed to work on Linux
machines and the transparent traffic capture modes are Linux specific and require iptables as well.

Additionally the Linux client depends on [psutil](https://pypi.python.org/pypi/psutil).

##Getting started
See [docs/getting_started.md](docs/getting_started.md) for setup and a walkthrough of nogotofail.

##Discussion
For discussion please use our [nogotofail Google Group](https://groups.google.com/forum/#!forum/nogotofail).
