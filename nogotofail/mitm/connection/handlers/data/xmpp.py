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


@handler(handlers, default=False)
class XmppStartTlsStripHandler(DataHandler):

    name = "xmppstarttlsstrip"
    description = "Suppress STARTTLS in XMPP streams"
    first_chunk_checked = False
    xmpp_detected = False
    starttls_feature_stripped = False
    vuln_notified = False

    def on_request(self, request):
        return self.on_chunk_received(request)

    def on_response(self, response):
        return self.on_chunk_received(response)

    def on_chunk_received(self, data):
        if not self.first_chunk_checked:
            self.first_chunk_checked = True
            self.xmpp_detected = self.is_xmpp_start(data)
            if self.xmpp_detected:
                self.log(logging.DEBUG, "XMPP detected")

        if not self.xmpp_detected:
            return data

        # Consider dropping TLS/SSL. However, this will likely destroy
        # connectivity if STARTTLS stripping does not work.
        # if data[0] == 0x16:
        #     self.log(logging.INFO, "Dropping TLS/SSL chunk")
        #     return ""

        if self.starttls_feature_stripped:
            # Ignore/pass through starttls, proceed, and failure messages
            if (data == '<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>' or
                data == '<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>' or
                data == '<failure xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'):
                return data

            if not self.vuln_notified:
                self.log(logging.CRITICAL, "Cleartext traffic after stripped STARTTLS")
                self.log_event(
                    logging.ERROR,
                    connection.AttackEvent(
                        self.connection, self.name, True,
                        None))
                self.connection.vuln_notify(util.vuln.VULN_XMPP_STARTTLS_STRIP)
                self.vuln_notified = True

        if not self.is_stream_features_present(data):
            return data

        self.log(logging.DEBUG, "XMPP stream features detected")
        if not self.is_starttls_feature_present(data):
            self.log(logging.WARNING, "XMPP STARTTLS feature missing")
            return data

        modified_data = self.strip_starttls_feature(data)
        if data == modified_data:
            self.log(logging.WARNING, "Failed to strip XMPP STARTTLS")
            return data
        self.starttls_feature_stripped = True
        self.log(logging.INFO, "Stripped XMPP STARTTLS")
        return modified_data

    def is_xmpp_start(self, data):
        return data.startswith("<stream:stream")

    def is_stream_features_present(self, data):
        return data.find("<stream:features") != -1

    def is_starttls_feature_present(self, data):
        return data.find("<starttls") != -1

    def strip_starttls_feature(self, data):
        start_index = data.find("<starttls")
        if start_index == -1:
            return data
        end_index = data.find("/starttls>", start_index)
        if end_index != -1:
            end_index += len("/starttls>")
        end_index2 = data.find(">", start_index)
        if end_index2 != -1 and data[end_index2 - 1] == '/':
            if end_index == -1 or end_index2 < end_index:
                end_index = end_index2
        return data[:start_index] + data[end_index:]


@handler(handlers, default=True)
class XmppAuthHandler(DataHandler):

    name = "xmppauthdetection"
    description = "Detect authentication credentials in XMPP traffic"
    first_chunk_checked = False
    xmpp_detected = False

    def on_request(self, request):
        return self.on_chunk_received(request)

    def on_response(self, response):
        return self.on_chunk_received(response)

    def on_chunk_received(self, data):
        if not self.first_chunk_checked:
           self.first_chunk_checked = True
           self.xmpp_detected = self.is_xmpp_start(data)
           if self.xmpp_detected:
               self.log(logging.DEBUG, "XMPP detected")

        if not self.xmpp_detected:
            return data

        if "<auth " in data:
            self.log(
                logging.CRITICAL,
                "Authentication credentials in XMPP traffic")
            self.log_event(
                logging.ERROR,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    None))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_AUTH)

        return data

    def is_xmpp_start(self, data):
        return data.startswith("<stream:stream")

