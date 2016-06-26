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
from nogotofail.mitm.util.http import HTTPRequestWrapper, HTTPResponseWrapper

# HTTP request and response valid "content-type" header values
VALID_CONTENT_TYPES = ["text/html", "application/json",
                       "text/plain", "text/xml", "application/xml"]
# HTTP headers to ignore not containing PII
IGNORE_HEADERS = ["host", "connection", "content-length", "accept",
                  "user-agent", "content-type", "accept-encoding",
                  "accept-language", "accept-charset"]


class HTTPPiiRequestWrapper(HTTPRequestWrapper):
    """ Wrapper for theHTTPRequestWrapper class to provide PII specific
        properties for HTTP request object. """

    def __init__(self, a_http_request):
        super(HTTPPiiRequestWrapper, self).__init__(a_http_request)

    @property
    def pii_headers_dict(self):
        """ Returns the request headers as a dictionary of types which can
            hold PII."""
        # Remove headers which won't contain PII
        valid_pii_headers = {k: v for k, v in self.headers_dict.iteritems()
                         if k not in IGNORE_HEADERS}
        return valid_pii_headers

    @property
    def pii_message_body(self):
        """ Returns the HTTP request message body content for content types
            which could contain PII. Compressed content is uncompressed."""
        http_content = ""
        headers = self.headers_dict
        content_len = int(headers.get("content-length", 0))
        content_type = headers.get("content-type", "")
        # Retrieve content from HTTP request message body
        if (content_len > 0 and content_type in VALID_CONTENT_TYPES):
            http_content = self.http_request.rfile.read(content_len)
        return http_content


class HTTPPiiResponseWrapper(HTTPResponseWrapper):
    """ Wrapper for theHTTPResponseWrapper class to provide PII specific
        properties for HTTP response object. """

    def __init__(self, a_http_response):
        super(HTTPPiiResponseWrapper, self).__init__(a_http_response)

    @property
    def pii_message_body(self):
        """ Returns the HTTP response message body content for content types
            which could contain PII. Compressed content is uncompressed."""
        headers = self.headers_dict
        content_type = headers.get("content-type", "")
        # Retrieve content from HTTP request message body
        if (content_type in VALID_CONTENT_TYPES):
            http_content = self.message_body
        return http_content
