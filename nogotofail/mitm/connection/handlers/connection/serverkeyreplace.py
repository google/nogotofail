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
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.util.tls import tls
from nogotofail.mitm.util.tls.types import Alert, Extension, HandshakeMessage, OpaqueMessage, TlsRecord
from nogotofail.mitm.event import connection

@handler(handlers, default=True)
class ServerKeyReplacementMITM(LoggingHandler):

    # IMPLEMENTATION NOTE: This forces a full TLS/SSL handshake using an (EC)DH
    # key exchange, flips a bit in the signature inside the ServerKeyExchange
    # message from the server, and checks that the client immediately aborts the
    # handshake with a fatal alert. If the client proceeds, it means that the
    # client did not verify that the server possesses the private key
    # corresponding to the public key in the server's certificate. If so, the
    # (EC)DH key exchange is not authenticated and is thus MiTMable.
    #
    # A downside of rewriting the ClientHello to force an (EC)DH key exchange is
    # that the server might not support any (EC)DH cipher suites in which case
    # it will abort the handshake. A better solution would be for this daemon to
    # pretend to be the server and offer only (EC)DH cipher suites. However, in
    # that setup we currently do not have an easy way to modify the
    # ServerKeyExchange message or use a server certificate chain that does not
    # match the server's private key.

    name = "serverkeyreplace"
    description = "Tests for clients vulnerable to SSL server key substitution"
    clienthello_adjusted = False
    signature_tampered = False
    first_alert_received_after_tampering = None
    vuln_detected = False
    buffer = ""

    def on_ssl(self, hello):
        self.ssl = True
        return False

    def on_request(self, request):
        if not self.ssl:
            return request
        try:
            record, remaining = tls.parse_tls(request)
            message = record.messages[0]
            if not self.clienthello_adjusted:
                self.clienthello_adjusted = True
                hello = message.obj
                # Force a full handshake (and thus a key exchange) by preventing
                # session resumption by clearing session ID and SessionTicket.
                hello.session_id = []
                for ext in hello.extension_list:
                    if ext.type == Extension.TYPE.SESSIONTICKET:
                        ext.raw_data = []
                # Retain in ClientHello only cipher suites which require the
                # server to send a ServerKeyExchange message: emphemeral (EC)DH
                # and RSA_EXPORT cipher suites. Also retain pseudo/signalling
                # cipher suites because they don't affect this attack/test.
                hello.ciphers = [c for c in hello.ciphers
                    if ("_DHE_" in str(c) or
                       "_ECDHE_" in str(c) or
                       "_RSA_EXPORT_" in str(c) or
                       str(c).endswith("_SCSV"))]
                return record.to_bytes()
            if self.signature_tampered:
                # The client MUST reply with an alert and close the connection.
                # Just closing the connection is also acceptable.
                if not self.first_alert_received_after_tampering:
                    if isinstance(message, Alert):
                        self.first_alert_received_after_tampering = message
                        return request

                self.vuln_detected = True
                self.log(
                    logging.CRITICAL,
                    ("Client is vulnerable to server key substitution"
                    " attack! Client reply: %s" % str(message)))
                self.connection.vuln_notify(
                    util.vuln.VULN_TLS_SERVER_KEY_REPLACEMENT)
                self.log_attack_event()
                self.connection.close()
                return request

        except ValueError:
            # Failed to parse TLS, this is probably due to a short read of a TLS
            # record.
            pass
        return request

    def _tamper_with_server_key_exchange(self, record, msg_index):
        server_key_exchange = record.messages[msg_index].obj
        # Flip a bit in the signature. This is a good way to test the client's
        # reaction the us replacing the server's (EC)DH public key in this
        # message. Flipping a bit in the signature is way easier than replacing
        # the public key.
        # The signature is at the end of the ServerKeyExchange message. It
        # should be safe to flip the tenth byte from the end because signatures
        # of all expected types (RSA, ECDSA, DSA) are longer than ten bytes.
        body = server_key_exchange.to_bytes()
        body = body[:-10] + chr(ord(body[-10]) ^ 1) + body[-9:]
        server_key_exchange = OpaqueMessage(body)
        record.messages[msg_index].obj = server_key_exchange
        return record.to_bytes()

    def on_response(self, response):
        if not self.ssl or self.signature_tampered:
            return response
        response = self.buffer + response
        self.buffer = ""
        # Tamper with the ServerKeyExchange message.
        try:
            remaining = response
            new_response = ""
            while remaining:
                record, remaining = tls.parse_tls(remaining, throw_on_incomplete=True)
                version = record.version
                for i, message in enumerate(record.messages):
                    if (isinstance(message, HandshakeMessage)
                        and (message.type ==
                            HandshakeMessage.TYPE.SERVER_KEY_EXCHANGE)):
                        tampered_record_bytes = (
                            self._tamper_with_server_key_exchange(record, i))
                        response = (new_response +
                            tampered_record_bytes +
                            remaining)
                        self.signature_tampered = True
                        return response
                    else:
                        new_response += record.to_bytes()

        except tls.types.TlsNotEnoughDataError:
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

    def on_close(self, handler_initiated):
        if self.signature_tampered and not self.vuln_detected:
            if self.first_alert_received_after_tampering:
                self.log(
                    logging.DEBUG,
                    ("Client not vulnerable to server key substitution attack."
                    " Client reply: %s"
                    % str(self.first_alert_received_after_tampering)))
            else:
                self.log(
                    logging.DEBUG,
                    ("Client not vulnerable to server key substitution attack."
                    " No reply received from client -- connection closed."))
            self.log_attack_event(success=False)
        return super(ServerKeyReplacementMITM, self).on_close(handler_initiated)
