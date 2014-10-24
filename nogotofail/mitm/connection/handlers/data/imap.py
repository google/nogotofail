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
import re


@handler(handlers, default=False)
class ImapStartTlsStripHandler(DataHandler):

    name = "imapstarttlsstrip"
    description = "Suppress STARTTLS in IMAP"

    first_server_chunk_received = False
    first_client_chunk_received = False
    imap_detected = False
    server_greeting_pattern = re.compile("\* OK[ \r\n]", re.I)
    server_capability_pattern = re.compile("\* CAPABILITY ", re.I)
    client_starttls_pattern = re.compile("[^ ]+ STARTTLS", re.I)

    server_starttls_stripped = False
    client_starttls_rejected = False

    vuln_notified = False

    def on_response(self, response):
        if not self.first_server_chunk_received:
            self.first_server_chunk_received = True
            if (not self.first_client_chunk_received and
                self.server_greeting_pattern.match(response)):
                self.imap_detected = True
                # Some servers advertise STARTTLS capability in their initial
                # response -- strip STARTTLS just in case.
                starttls_index = response.lower().find(" starttls")
                if starttls_index != -1:
                    response = response[:starttls_index] + \
                               response[starttls_index + len(" starttls"):]
                return response

        if not self.imap_detected:
            return response

        if self.server_capability_pattern.match(response):
            # CAPABILITY reply from server -- strip STARTTLS from the list
            starttls_index = response.lower().find(" starttls")
            if starttls_index != -1:
                response = response[:starttls_index] + \
                           response[starttls_index + len(" starttls"):]
                self.server_starttls_stripped = True
                self.log(logging.DEBUG, "Stripped STARTTLS from server reply")
            return response

        return response


    def on_request(self, request):
        self.first_client_chunk_received = True
        if not self.imap_detected:
            return request

        if self.client_starttls_rejected:
            if not self.vuln_notified:
                self.log(
                    logging.CRITICAL,
                    "Cleartext traffic after stripped STARTTLS")
                self.log_event(
                    logging.ERROR,
                    connection.AttackEvent(
                        self.connection, self.name, True,
                        None))
                self.connection.vuln_notify(
                    util.vuln.VULN_IMAP_STARTTLS_STRIP)
                self.vuln_notified = True
                # Stop analyzing/attacking this connection
                self.imap_detected = False
        elif self.client_starttls_pattern.match(request):
            # Client is attempting STARTTLS -- fake a rejection reply from
            # server and do not forward STARTTLS to server.
            self.client_starttls_rejected = True
            self.log(logging.DEBUG, "Suppressed STARTTLS from client")
            tag = request[:request.find(" ")]
            self.connection.client_socket.sendall(
                tag + " BAD STARTTLS unavailable\r\n")
            return ""

        return request


@handler(handlers, default=True)
class ImapAuthHandler(DataHandler):

    name = "imapauthdetection"
    description = "Detect authentication credentials in IMAP traffic"

    first_server_chunk_received = False
    first_client_chunk_received = False
    imap_detected = False
    server_greeting_pattern = re.compile("\* OK[ \r\n]", re.I)
    client_auth_pattern = re.compile("[^ ]+ LOGIN|[^ ]+ AUTHENTICATE", re.I)

    def on_response(self, response):
        if not self.first_server_chunk_received:
            self.first_server_chunk_received = True
            if (not self.first_client_chunk_received and
                self.server_greeting_pattern.match(response)):
                self.imap_detected = True

        return response

    def on_request(self, request):
        self.first_client_chunk_received = True
        if not self.imap_detected:
            return request

        if self.client_auth_pattern.match(request):
            self.log(
                logging.CRITICAL,
                "Authentication credentials in cleartext IMAP traffic")
            self.log_event(
                logging.ERROR,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    None))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_AUTH)

        return request

