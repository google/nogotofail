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
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm import util
from nogotofail.mitm.util import ssl2, tls, vuln
from nogotofail.mitm.util.tls.types import HandshakeMessage, TlsRecord


@handler.passive(handlers)
class InsecureCipherDetectionHandler(DataHandler):
    name = "insecurecipherdetection"
    description = "Detect insecure ciphers in TLS Client Hellos"

    def _handle_bad_ciphers(self, ciphers, message):
            self.log(logging.ERROR, message)
            self.log_attack_event(data=ciphers)
            self.connection.vuln_notify(vuln.VULN_WEAK_CIPHER)

    def on_ssl(self, client_hello):

        # Check for anon ciphers, these don't verify the identity of the
        # endpoint
        anon_ciphers = [str(c) for c in client_hello.ciphers if "_anon_" in str(c)]
        if anon_ciphers:
            self._handle_bad_ciphers(anon_ciphers,
                "Client enabled anonymous TLS/SSL cipher suites %s" %
                (", ".join(anon_ciphers)))

        # Check for NULL encryption ciphers
        null_ciphers = [str(c) for c in client_hello.ciphers if "_WITH_NULL_" in str(c)]
        if null_ciphers:
            self._handle_bad_ciphers(null_ciphers,
                "Client enabled NULL encryption TLS/SSL cipher suites %s" %
                (", ".join(null_ciphers)))

        # Check for NULL integrity ciphers
        integ_ciphers = [str(c) for c in client_hello.ciphers if str(c).endswith("_NULL")]
        if integ_ciphers:
            self._handle_bad_ciphers(integ_ciphers,
                "Client enabled NULL integrity TLS/SSL cipher suites %s" %
                (", ".join(integ_ciphers)))

        # Check for export ciphers since they're horribly weak
        export_ciphers = [str(c) for c in client_hello.ciphers if "EXPORT" in str(c)]
        if export_ciphers:
            self._handle_bad_ciphers(integ_ciphers,
                "Client enabled export TLS/SSL cipher suites %s" %
                (", ".join(export_ciphers)))


@handler.passive(handlers)
class WeakTLSVersionDetectionHandler(DataHandler):
    name = "weaktlsversiondetection"
    description = "Detect versions of the TLS/SSL protocols that are known to be weak"

    def on_ssl(self, client_hello):
        if isinstance(client_hello, ssl2.types.ClientHello):
            self.log(logging.ERROR, "Client enabled SSLv2 protocol")
            self.log_attack_event(data="SSLv2")
            self.connection.vuln_notify(vuln.VULN_WEAK_TLS_VERSION)
            return
        if (isinstance(client_hello, tls.types.ClientHello) and
                client_hello.version.major == 3 and
                client_hello.version.minor == 0):
            # SSLv3 is still used in fallback situations and ngtf tends to cause
            # these fallback situations so we wont notify the client of these
            # vulns to prevent spamming. We will log if TLS_FALLBACK_SCSV is set
            # since it should be set in fallback situations.
            fallback = ("TLS_FALLBACK_SCSV" in
                    [str(c) for c in client_hello.ciphers])
            if fallback:
                self.log(logging.WARNING,
                        "Client enabled SSLv3 protocol with TLS_FALLBACK_SCSV")
            else:
                self.log(logging.ERROR,
                        "Client enabled SSLv3 protocol without TLS_FALLBACK_SCSV")
            self.log_attack_event(data="SSLv3")


@handler.passive(handlers)
class NoForwardSecrecy(DataHandler):
    name = "noforwardsecrecy"
    description = (
        "Detects selected server cipher suites which don't support "
        "Diffie-Hellman key exchange (DHE or ECDHE) i.e. in "
        "SERVER_HELLO response")

    buffer = ""
    ssl = False

    def on_ssl(self, client_hello):
        self.ssl = True
        self.client_session_id = client_hello.session_id
        return False

    def on_response(self, response):
        if not self.ssl:
            return response
        response = self.buffer + response
        self.buffer = ""
        try:
            index = 0
            while index < len(response):
                record, size = TlsRecord.from_stream(response[index:])
                for i, message in enumerate(record.messages):
                    # Check for Server Hello message
                    if (isinstance(message, tls.types.HandshakeMessage) and
                            message.type == HandshakeMessage.TYPE.SERVER_HELLO):
                        server_hello = message.obj
                        selected_cipher = str(server_hello.cipher)

                        _connection = self.connection
                        destination = _connection.hostname if \
                            _connection.hostname else _connection.server_addr
                        debug_message = ["Selected cipher \"", selected_cipher,
                                "\" for connection to \"", destination, "\""]
                        self.log(logging.DEBUG, "".join(debug_message))
                        """ Check if Ephemeral Diffie-Hellman key exchange is
                            used in selected cipher """
                        fs_key_strings = ["DHE", "ECDHE"]
                        if not [fs_string for fs_string in fs_key_strings
                                if fs_string in selected_cipher]:
                            error_message = \
                                ["Cipher suite key exhange technqiue doesn't ",
                                 "support forward secrecy. ",
                                 "Cipher suite - [", selected_cipher, "]"]
                            self.log(logging.WARNING, "".join(error_message))
                            self.log_event(logging.WARNING,
                                connection.AttackEvent(
                                    self.connection, self.name, True, ""))
                            self.connection.vuln_notify(
                                util.vuln.VULN_NO_FORWARD_SECRECY)
                        return response
                index += size
        except ValueError:
            # Failed to parse TLS, this is probably due to a short read of a TLS
            # record. Buffer the response to try and get more data.
            self.buffer = response
            # But don't buffer too much, give up after 16k.
            if len(self.buffer) > 2**14:
                response = self.buffer
                self.buffer = ""
                return self.buffer
            return ""
        return response
