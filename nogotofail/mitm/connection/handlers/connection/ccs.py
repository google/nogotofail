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
from nogotofail.mitm.event import connection


@handler(handlers, default=True)
class EarlyCCS(LoggingHandler):

    name = "earlyccs"
    description = "Tests for OpenSSL early CCS vulnerability(CVE-2014-0224)"
    injected_server = False
    bridge = False

    def on_ssl(self, hello):
        self.ssl = True
        self.client_session_id = hello.session_id
        return False

    def on_request(self, request):
        if not self.ssl or self.bridge:
            return request
        try:
            if self.injected_server:
                record, size = tls.types.TlsRecord.from_stream(request)
                message = record.messages[0]
                if self.injected_server:
                    # OpenSSL after the EarlyCCS fix should send an unexpcted
                    # message error. Some other libraries send a close_notify so
                    # accept that as well.
                    if not (
                        isinstance(message, tls.types.Alert) and ((message.description == 10 and
                            message.level == 2) or message.description == 0)):
                        self.log(
                            logging.CRITICAL,
                            "Client is vulnerable to Early CCS attack!")
                        self.connection.vuln_notify(util.vuln.VULN_EARLY_CCS)
                        self.log_event(
                            logging.CRITICAL,
                            connection.AttackEvent(
                                self.connection,
                                self.name, True, None))

                        self.connection.close()
                        self.bridge = True
                    else:
                        self.log(
                            logging.DEBUG,
                            "Client not vulnerable to early CCS")
                        self.log_event(
                            logging.INFO,
                            connection.AttackEvent(
                                self.connection,
                                self.name, False, None))

        except ValueError:
            # Failed to parse TLS, this is probably due to a short read of a TLS
            # record.
            pass
        return request

    def on_response(self, response):
        if not self.ssl or self.bridge or self.injected_server:
            return response
        try:
            index = 0
            while index < len(response):
                record, size = tls.types.TlsRecord.from_stream(response[index:])
                index += size
                version = record.version
                for i, message in enumerate(record.messages):
                    # Inject the CCS right after the ServerHello
                    if isinstance(message, tls.types.HandshakeMessage) and message.type == 2:
                        server_hello = message.obj
                        # Remove session id and extensions to prevent resumption
                        # Otherwise a CCS will follow a ServerHello
                        server_hello.extension_list = []
                        server_hello.session_id = []

                        ccs = tls.types.TlsRecord(
                            20, record.version,
                            [tls.types.ChangeCipherSpec(1)])
                        rec = tls.types.TlsRecord(22, record.version, [message])
                        done = tls.types.TlsRecord(
                            22, record.version,
                            [tls.types.ServerHelloDone()])
                        response = (
                            rec.to_bytes() + ccs.to_bytes() + done.to_bytes())
                        self.injected_server = True

                        return response

        except ValueError:
            # Failed to parse TLS, this is probably due to a short read of a TLS
            # record.
            pass
        return response
