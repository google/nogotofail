r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
import tempfile
import OpenSSL.crypto
import os
import random


class CertificateAuthority(object):
    """Simple CA for generating certs based on CNs and sans."""

    def __init__(self, ca_file='ca.pem', cert_dir=tempfile.gettempdir()):
        self.ca_file = ca_file
        self.cert_dir = cert_dir
        if not os.path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

    def _generate_ca(self):
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        self.cert = OpenSSL.crypto.X509()
        self.cert.set_version(2)
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = 'ca.nogotofail'
        self.cert.set_notBefore("19300101000000+0000")
        self.cert.set_notAfter("203012310000+0000")
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            OpenSSL.crypto.X509Extension(
                'basicConstraints',
                True,
                'CA:TRUE, pathlen:1'),
            OpenSSL.crypto.X509Extension(
                'keyUsage',
                True,
                'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(
                'subjectKeyIdentifier',
                False,
                'hash',
                subject=self.cert)])
        self.cert.sign(self.key, 'sha1')

        with open(self.ca_file, 'w') as f:
            f.write(
                OpenSSL.crypto.dump_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM,
                    self.key))
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    self.cert))

    def _read_ca(self, file):
        with open(file) as f:
            contents = f.read()
        self.key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, contents)
        self.cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, contents)

    def _generate_cert(self, cn, san, path):
        """Generate a certificate using cn and san and store it at path"""
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        cert.get_subject().CN = cn
        cert.set_pubkey(key)
        cert.set_serial_number(random.randint(0, 2**20))
        # Use a huge range so we dont have to worry about bad clocks
        cert.set_notBefore("19300101000000+0000")
        cert.set_notAfter("203012310000+0000")
        cert.set_issuer(self.cert.get_subject())
        if san:
            cert.add_extensions([san])
        cert.sign(self.key, 'sha1')

        with open(path, 'w') as f:
            f.write(
                OpenSSL.crypto.dump_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM,
                    key))
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert))


    def get_cert(self, cn, san):
        """Get a signed certificate for a cn, san.
        cn: The common name to use in the certificate
        san: The subject alt name to add to the certificate, or None

        Returns a path to a pem file containing the key and cert"""
        san_str = san.get_data() if san else ''
        # TODO: Bake the CA into this so we don't conflict if we share a
        # cert_dir with another CA
        name_hash = hash(cn + san_str)
        path = os.path.sep.join([self.cert_dir, '.cert_%s.pem' % (name_hash)])
        if not os.path.exists(path):
            self._generate_cert(cn, san, path)
        return path
