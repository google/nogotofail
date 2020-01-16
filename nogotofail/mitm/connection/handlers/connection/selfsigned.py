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
import logging
from nogotofail.mitm import util
from nogotofail.mitm.connection.handlers import preconditions
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection


@handler(handlers, default=True)
class SelfSignedMITM(LoggingHandler):

    name = "selfsigned"
    description = (
        "Attempts to MiTM using a self-signed certificate for the requested "
        "domain.")
    ca = util.CertificateAuthority()
    certificate = None
    success = False
    vuln = util.vuln.VULN_TLS_SELF_SIGNED

    def on_request(self, request):
        if not self.success and self.ssl:
            self.log(logging.CRITICAL, "MITM Success! Cert file: %s"
                     % (self.certificate))
            self.log_event(
                logging.CRITICAL,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    self.certificate))
            self.success = True
            self.connection.vuln_notify(self.vuln)
        return super(SelfSignedMITM, self).on_request(request)

    def on_response(self, response):
        if not self.success and self.ssl:
            self.log(logging.CRITICAL, "MITM Success! Cert file: %s"
                     % (self.certificate))
            self.log_event(
                logging.CRITICAL,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    self.certificate))
            self.success = True
            self.connection.vuln_notify(self.vuln)
        return super(SelfSignedMITM, self).on_response(response)

    def on_ssl(self, client_hello):
        super(SelfSignedMITM, self).on_ssl(client_hello)
        return True

    def on_close(self, handler_initiated):
        super(SelfSignedMITM, self).on_close(handler_initiated)
        if not self.success:
            self.log_event(
                logging.INFO,
                connection.AttackEvent(
                    self.connection, self.name, False,
                    None))

    def on_certificate(self, server_cert):
        subject = server_cert.get_subject()
        for k, v in subject.get_components():
            if k == "CN":
                cn = v
        extensions = [server_cert.get_extension(i)
                      for i in range(server_cert.get_extension_count())]
        altnames = [extension for extension in extensions
                    if extension.get_short_name() == "subjectAltName"]
        san = altnames[0] if len(altnames) > 0 else None
        self.certificate = self.ca.get_cert(cn, san)
        return self.certificate

@handler(handlers, default=True)
@preconditions.requires_files(files=["superfish.pem"])
class SuperFishMITM(SelfSignedMITM):
    name = "superfishmitm"
    description = "Attempt a MiTM using the compromised superfish MITM CA"
    ca = util.CertificateAuthority("superfish.pem")
    vuln = util.vuln.VULN_TLS_SUPERFISH_TRUSTED

@handler(handlers, default=True)
@preconditions.requires_files(files=["explicit_curve.pem"])
class SuperFishMITM(SelfSignedMITM):
    name = "explicitcurvemitm"
    description = "Attempt a MiTM exploiting CVE-2020-0601"
    ca = util.CertificateAuthority("explicit_curve.pem")
    vuln = util.vuln.VULN_TLS_EXPLICIT_CURVE
