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
from nogotofail.mitm import util
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import HttpContentHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
import nogotofail.mitm.util.pii as piiutil
import logging


class HttpPiiContentHandler(HttpContentHandler):
    """ Provides methods for parsing the content of plaintext HTTP request and
        response objects for PII. """

    def on_request(self, request):
        http = util.http.parse_request(request)
        if http and not self.ssl and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            http_request = util.httppii.HTTPPiiRequestWrapper(http)
            self.on_http_request(http_request)
        return request

    def on_http_request(self, http_request):
        comment = "Code to be added in class inheriting this."

    def on_response(self, response):
        http = util.http.parse_response(response)
        if http:
            headers = dict(http.getheaders())
            host = headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            if not self.connection.ssl:
                http_response = util.httppii.HTTPPiiResponseWrapper(http)
                self.on_http_response(http_response)
        return response

    def on_http_response(self, http_response):
        comment = "Code to be added in class inheriting this."


@handler.passive(handlers)
class HttpPiiDetection(HttpPiiContentHandler):
    """ Detects PII appearing in plaintext HTTP request and response
        content. """

    name = "httppii"
    description = "Detect PII in clear text http requests and responses"

    def __init__(self, connection):
        super(HttpPiiDetection, self).__init__(connection)
        self.client = \
            self.connection.app_blame.clients.get(connection.client_addr)

    def on_http_request(self, http_request):
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
            # Fetch a dictionary of headers which could contain PII.
            valid_headers = http_request.pii_headers_dict
            if (valid_headers):
                valid_header_text = \
                    str(valid_headers.values()).translate(None, "[']")
                self._alert_on_pii_headers(valid_header_text, url)
            # Check for PII in HTTP message body
            msg_content = http_request.pii_message_body
            if msg_content:
                self._alert_on_pii_request_message_body(msg_content, url)

    def on_http_response(self, http_response):
        """ Method processes unencrypted (non-HTTPS) HTTP response message bodies
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
        error_message = ""
        # Check if PII found in query string
        pii_items_found = \
            self.client.pii_store.detect_pii_items(query_string)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(query_string)
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_QRY_STRING,
                  ": Personal items found in request query string ",
                  str(pii_items_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_QRY_STRING,
                  ": Location found in request query string ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)

    def _alert_on_pii_headers(self, header_text, url):
        """ Test and alert on instances of PII found in HTTP headers
        """
        pii_items_found = []
        pii_location_found = []
        # Check if PII found in message body
        pii_items_found = \
            self.client.pii_store.detect_pii_items(header_text)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(header_text)
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_HEADER,
                  ": Personal items found in request headers ",
                  str(pii_items_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_HEADER,
                 ": Location found in request headers ",
                 "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)

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
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Personal items found in request message body ",
                  str(pii_items_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Location found in request message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)

    def _alert_on_pii_response_message_body(self, msg_content, url):
        """ Test and alert on instances of PII found in HTTP message body
        """
        pii_items_found = []
        pii_location_found = []
        # Check if PII found in message body
        pii_items_found = \
            self.client.pii_store.detect_pii_items(msg_content)
        pii_location_found = \
            self.client.pii_store.detect_pii_location(msg_content)
        if (pii_items_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Personal items found in response message body ",
                  str(pii_items_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
        if (pii_location_found):
            error_message = [piiutil.CAVEAT_PII_MSG_BODY,
                  ": Location found in response message body ",
                  "(longitude, latitude) - ", str(pii_location_found)]
            self.log(logging.ERROR, "".join(error_message))
            self.log_event(logging.ERROR, connection.AttackEvent(
                           self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP_PII)
