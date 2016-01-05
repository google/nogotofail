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
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
import httplib
import re
import urlparse
import zlib


class HTTPRequest(BaseHTTPRequestHandler):
    """ Basic RequestHandler to try and parse a given request_text as an HTTP
        request. """

    def __init__(self, request_text):
        # sometimes path and headers don't get set in the object, set some
        # dummy ones so we don't have to check for them elsewhere.
        self.path = ""
        self.headers = {}
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message
    

class HTTPRequestWrapper(object):
    """ Wrapper class for the HTTPRequest object providing properties to access
        common request attributes.
        Note. The HTTPRequest object could not be readily extended as the
        parent class (BaseHTTPRequestHandler) doesn't inherit from 'object' """

    http_request = None

    def __init__(self, a_http_request):
        self.http_request = a_http_request

    @property
    def headers_dict(self):
        """ Returns the request headers as a dictionary with each name/value
            pair as header-name/header-value. """
        return dict(self.http_request.headers)

    @property
    def path(self):
        """ Returns the path for the HTTPRequest object."""
        return self.http_request.path

    @property
    def query_string(self):
        """ Returns the request query string as a string """
        # Extract query string from request url.
        url_parts = urlparse.urlparse(self.http_request.path)
        return url_parts[4]

    @property
    def query_string_dict(self):
        """ Returns the request query string as a dictionary with each
            key/value pair as parameter-name/parameter-value."""
        qs_dict = urlparse.parse_qs(self.query_string)
        return qs_dict

    @property
    def message_body(self):
        """ Returns the HTTP request message body content. Compressed content
            is uncompressed."""
        http_content = ""
        headers = dict(self.http_request.headers)
        content_len = int(headers.get("content-length", 0))
        # Retrieve content from HTTP request message body
        if (content_len > 0):
            http_content = self.http_request.rfile.read(content_len)
        return http_content


class HTTPResponseWrapper(object):
    """ Wrapper class for the HTTPResponse object providing properties to access
        common response attributes.
        Note. The HTTPResponse object could not be readily extended as it
        doesn't inherit from 'object' """

    http_response = None

    def __init__(self, a_http_response):
        self.http_response = a_http_response

    @property
    def response(self):
        """ Returns the HTTPResponse object."""
        return self.http_response

    @property
    def headers_dict(self):
        """ Returns the request headers as a dictionary with each name/value
            pair as header-name/header-value. """
        return dict(self.http_response.getheaders())

    @property
    def message_body(self):
        """ Returns the HTTP request message body content. Compressed content
            is uncompressed."""
        CHUNK_SIZE = 1024
        http_content = ""
        headers = dict(self.http_response.getheaders())
        content_type = headers.get("content-type", "")
        content_encoding = headers.get("content-encoding", "")
        content_chunk_list = []
        number_of_chunks = 0
        try:
            while True:
                content_chunk = self.http_response.read(CHUNK_SIZE)
                content_chunk_list.append(content_chunk)
                number_of_chunks += 1
                """ Stop reading HTTP content after all chunks are read """
                if not content_chunk:
                    break
                    """ Stop reading HTTP content after 2 chunks """
                elif ((content_type == "text/html" or
                       content_type == "text/plain") and
                      number_of_chunks == 2):
                    break
        except httplib.IncompleteRead, e:
            content_chunk = e.partial
            content_chunk_list.append(content_chunk)
        http_content = ''.join(content_chunk_list)
        # self.log(logging.DEBUG, "HTTP response headers: " + \
        #    "content-type - %s; content-encoding - %s" \
        try:
            """ Decompress compressed content """
            if ("deflate" in content_encoding or "gzip" in content_encoding):
                http_content = \
                    zlib.decompress(http_content, zlib.MAX_WBITS | 32)
                # self.log(logging.DEBUG, "HTTP Content - %s."
                #    % http_content)
        except zlib.error, e:
            """ Handling decompression of a truncated or partial file
                is read """
            zlib_partial = zlib.decompressobj(zlib.MAX_WBITS | 32)
            http_content = zlib_partial.decompress(http_content)
        return http_content


class _FakeSocket(StringIO):

    def makefile(self, *args, **kwargs):
        return self


def parse_request(request):
    """Try and parse request as an HTTP request.
    Returns a nogotofail.mitm.util.http.HTTPRequest if successful
    Returns None if request is not a HTTP request
    """
    # Sometimes HTTPRequest accepts weird things, so do a simple check for a
    # HTTP/.*\r\n before trying to parse
    if not re.match(".*HTTP/.*\r\n", request):
        return None
    http = HTTPRequest(request)
    if http.error_code:
        return None
    return http


def parse_response(response):
    """Try and parse response as an HTTP response.
    Returns a httplib.http.HTTPResponse if sucessful
    Returns None if response is not a HTTP response
    """
    s = _FakeSocket(response)
    response = httplib.HTTPResponse(s, strict=1)
    try:
        response.begin()
        return response
    except httplib.HTTPException:
        return None
