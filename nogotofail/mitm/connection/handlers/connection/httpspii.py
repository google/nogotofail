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
from nogotofail.mitm.connection.handlers import preconditions
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
from nogotofail.mitm import util
import nogotofail.mitm.util.pii as piiutil


class HttpsPiiContentHandler(LoggingHandler):

    name = "piidetection"
    description = "Detect HTTPS requests and responses and allow \
        classes that inherit from this to process content"

    ssl = False

    def __init__(self, connection):
        super(HttpsPiiContentHandler, self).__init__(connection)
        self.client = \
            self.connection.app_blame.clients.get(connection.client_addr)

    def on_ssl(self, client_hello):
        self.client_session_id = client_hello.session_id
        return True

    def on_ssl_establish(self):
        self.ssl = True

    def on_request(self, request):
        http = util.http.parse_request(request)
        if http and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            # Call the specific http request handler based on the use of TLS
            if self.ssl:
                http_request = util.httppii.HTTPPiiRequestWrapper(http)
                self.on_https_request(http_request)
        return request

    def on_https_request(self, http_request):
        comment = "Code to be added in class inheriting this."

    def on_response(self, response):
        http = util.http.parse_response(response)
        if http:
            try:
                headers = dict(http.getheaders())
                host = headers.get("host", self.connection.server_addr)
            except AttributeError:
                host = self.connection.server_addr
            if not self.connection.hostname:
                self.connection.hostname = host
            # Call the specific http response handler based on the use of TLS
            if self.ssl:
                http_response = util.httppii.HTTPPiiResponseWrapper(http)
                self.on_https_response(http_response)
        return response

    def on_https_response(self, http_response):
        comment = "Code to be added in class inheriting this."


@handler(handlers, default=True)
@preconditions.requires_files(files=["mitm_key_cert_chain.pem"])
class HttpsPiiDetection(HttpsPiiContentHandler):

    name = "httpspii"
    description = (
        "Testing to see if encrypted PII is present in HTTPS content.")
    # Location of trusted MitM certificate.
    MITM_CA = "./mitm_key_cert_chain.pem"
    ca = util.CertificateAuthority(MITM_CA)
    certificate = None

    def on_certificate(self, server_cert):
        """ Terminate on_certificate interaction between server and client &
            insert a trusted certificate in traffic to server to initiate a
            MitM attack
        """
        subject = server_cert.get_subject()
        for k, v in subject.get_components():
            if k == "CN":
                cn = v
        debug_message = ["Generating MitM TLS certificate with CN - ", cn]
        self.log(logging.DEBUG, "".join(debug_message))
        extensions = [server_cert.get_extension(i)
                      for i in range(server_cert.get_extension_count())]
        altnames = [extension for extension in extensions
                    if extension.get_short_name() == "subjectAltName"]
        san = altnames[0] if len(altnames) > 0 else None
        self.certificate = self.ca.get_cert(cn, san)
        return self.certificate

    def on_https_request(self, http_request):
        """ Parse HTTPS requests for PII paramters
        """
        if (self.client and http_request):
            headers = http_request.headers_dict
            host = headers.get("host", self.connection.server_addr)
            url = host + http_request.path
            # Extract query string from request url.
            query_string = http_request.query_string
            # Check for PII in HTTP query string
            if (query_string):
                self._alert_on_pii_query_string(query_string, url)
            # Check for PII in HTTP headers
            valid_header_text = ""
            # Remove headers which won't contain PII
            valid_headers = http_request.pii_headers_dict
            if (valid_headers):
                valid_header_text = \
                    str(valid_headers.values()).translate(None, "[']")
                self._alert_on_pii_headers(valid_header_text, url)
            # Check for PII in HTTP message body
            msg_content = http_request.pii_message_body
            if msg_content:
                self._alert_on_pii_request_message_body(msg_content, url)

    def on_https_response(self, http_response):
        """ Parse HTTPS responses for PII paramters
        """
        if (self.client and http_response):
            url = ""
            msg_content = http_response.message_body
            # Check for PII in HTTP message body
            self._alert_on_pii_response_message_body(msg_content, url)

    def _alert_on_pii_query_string(self, query_string, url):
        """ Test and alert on instances of PII found in query string
        """
        pii_items_found = []
        pii_location_found = []
        # Check if PII found in query string
        pii_items_found = \
            self.client.pii_store.detect_pii_items(query_string)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(query_string)
        # If PII is found in query string raise INFO message in
        # message and event logs
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_QRY_STRING,
                  ": Personal IDs found in request query string ",
                  str(pii_items_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_QRY_STRING,
                  ": Location found in request query string ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))

    def _alert_on_pii_headers(self, header_text, url):
        """ Test and alert on instances of PII found in HTTP headers
        """
        pii_items_found = []
        pii_location_found = []
        # Check if PII found in header
        pii_items_found = \
            self.client.pii_store.detect_pii_items(header_text)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(header_text)
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_HEADER,
                  ": Personal IDs found in request headers ",
                  str(pii_items_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_HEADER,
                 ": Location found in request headers ",
                 "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))

    def _alert_on_pii_request_message_body(self, msg_content, url):
        """ Test and alert on instances of PII found in HTTP message body
        """
        pii_items_found = []
        pii_location_found = []
        # Check if PII found in message body
        pii_items_found = \
            self.client.pii_store.detect_pii_items(msg_content)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(msg_content)
        # If PII is found in message body raise INFO message in
        # message and event logs
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Personal IDs found in request message body ",
                  str(pii_items_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Location found in request message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))

    def _alert_on_pii_response_message_body(self, msg_content, url):
        """ Test and alert on instances of PII found in HTTP message body
        """
        pii_items_found = []
        pii_location_found = []
        # Check if PII found in query string
        pii_items_found = \
            self.client.pii_store.detect_pii_items(msg_content)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(msg_content)
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Personal IDs found in response message body ",
                  str(pii_items_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Location found in response message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.INFO, "".join(error_message))
            self.log_event(logging.INFO, connection.AttackEvent(
                           self.connection, self.name, True, url))
