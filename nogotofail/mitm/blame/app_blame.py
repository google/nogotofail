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
from collections import namedtuple
import logging
import socket
import select
import sys
import ssl
import time
import urllib

from nogotofail.mitm.connection import handlers
from nogotofail.mitm.connection.handlers import preconditions
from nogotofail.mitm.util import close_quietly

Application = namedtuple("Application", ["package", "version"])


class Client(object):
    """Class representing a blame client connection.
    NOTE: You should avoid using this directly for client queries because if the client reconnects
    a new Client will be made."""
    CLIENT_TIMEOUT = 21600

    class Callback(object):
        def __init__(self, fn, timeout, now=None):
            self.fn = fn
            self.timeout = timeout
            self.start = now or time.time()

    def __init__(self, socket, server, now=None):
        self.socket = socket
        self.server = server
        self.info = None
        self.last_used = now or time.time()
        if isinstance(socket, ssl.SSLSocket):
            self._select_fn = self._ssl_handshake_select_fn
        else:
            self._select_fn = self._handshake_select_fn
        self.queries = {}
        self._txid = 0
        self._buffer = ""
        self.address = self.socket.getpeername()[0]
        self.logger = logging.getLogger("nogotofail.mitm")
        self._handshake_completed = False

    @property
    def available(self):
        """Returns if the client is currently available."""
        return self._handshake_completed

    @property
    def next_txid(self):
        """Returns the next unused transaction id for a blame request."""
        id = self._txid
        self._txid += 1
        return id

    def on_select(self):
        """Should be called when select has returned self.socket as ready for reading."""
        self.last_used = time.time()
        return self._select_fn()

    def check_timeouts(self):
        """Returns if the connection or any of its callbacks have timed out."""
        now = time.time
        if now - self.last_used > self.CLIENT_TIMEOUT:
            return False
        for callback in self.queries.values():
            if now >= callback.start + callback.timeout and callback.timeout != 0:
                return False
        return True

    def close(self):
        """Close the connection to the client. This also notifies all pending queries that their
        request has failed."""
        close_quietly(self.socket)
        for callback in self.queries.values():
            callback.fn(False)

    def get_applications_async(
            self, client_port, server_addr, server_port, callback, timeout=10):
        """See Server.get_applications_async"""

        self.last_used = time.time()
        txid = self.next_txid

        family = socket.AF_INET6 if ":" in server_addr else socket.AF_INET
        message = (
            unicode(
                "%d tcp_client_id %s %s %s\n" %
                (txid, client_port,
                 socket.inet_pton(family, server_addr).encode("hex"),
                 server_port)))
        try:
            self.socket.sendall(message)
        except socket.error as e:
            self.logger.info(
                "Blame: Error sending vuln_notify to %s: %s." % (self.address, e))
            return False

        self.queries[txid] = Client.Callback(
                self._generate_on_get_applications_fn(callback), timeout)
        return True

    def vuln_notify_async(self, server_addr, server_port, id,
            type, applications, callback, timeout=10):
        """See Server.vuln_notify_async."""

        self.last_used = time.time()
        txid = self.next_txid

        message = unicode("%d vuln_notify %s %s %s %d %s\n" %
            (txid, id, type, server_addr, server_port,
             ", ".join(
                 ["%s %s" % (urllib.quote(app.package), app.version) for app in applications])))
        try:
            self.socket.sendall(message)
        except socket.error as e:
            self.logger.info("AppBlame notify error for %s, %s." % (self.address, e))
            return False

        self.queries[txid] = Client.Callback(
                self._generate_on_vuln_notify_fn(callback), timeout)
        return True

    def _generate_on_vuln_notify_fn(self, callback):
        def on_vuln_notify(success, data=None):
            if not success:
                callback(False)
                self.server.remove_client(self.address)
                return
            callback(True, data == "OK")
        return on_vuln_notify

    def _generate_on_get_applications_fn(self, callback):
        def on_get_applications(success, data=None):
            if not success:
                callback(False)
                self.server.remove_client(self.address)
                return

            platform_info = self.info.get(
                "Platform-Info", "Unknown")
            apps = data.split(",")
            try:
                callback(True, platform_info,
                        [Application(*map(urllib.unquote, app.strip().split(" ", 1)))
                            for app in apps])
            except (ValueError, TypeError):
                callback(False)
        return on_get_applications

    def _ssl_handshake_select_fn(self):
        self.socket.setblocking(False)
        try:
            self.socket.do_handshake()
        except socket.error:
            return True
        self.socket.setblocking(True)
        self._select_fn = self._handshake_select_fn
        return True

    def _handshake_select_fn(self):
        """Handle client data during the handshake."""
        try:
            data = self.socket.recv(8192)
        except socket.error:
            self.logger.info("Blame: Erorr reading from client %s.", self.address)
            return False
        if not data:
            self.logger.info("Blame: Client %s closed connection.", self.address)
            return False
        data = self._buffer + data
        lines = data.split("\n")
        # Check if there is still more data to be read.
        # Some clients send \r\n line endings and some \n, so strip extra
        # whitespace.
        if lines[-1].strip() != "":
            self._buffer = data
            return
        data = data.replace("\r", "")
        lines = data[:data.index("\n\n")].split("\n")
        try:
            self._parse_headers(lines)
            self._send_headers()
        except (ValueError, KeyError, IndexError, socket.error) as e:
            try:
                self.socket.sendall("400 Error parsing message\n\n")
            except socket.error:
                pass
            self.logger.info("Blame: Bad handshake from %s: %s" % (self.address, e))
            return False
        # TODO: Handle any extra data after the handshake, there shouldn't be
        # any in the current version of the protocol.
        # Done!
        self.logger.info("Blame: New client from %s", self.address)
        self._select_fn = self._response_select_fn
        self._handshake_completed = True
        return True

    def _send_headers(self):
        # Send the OK
        self.socket.sendall("0 OK\n")
        # Send the configs
        prob = self.info.get("Attack-Probability", self.server.default_prob)
        self.socket.sendall("Attack-Probability: %f\n" % prob)
        attacks = self.info.get("Attacks", self.server.default_attacks)
        attacks_str = ",".join([attack.name for attack in attacks])
        self.socket.sendall("Attacks: %s\n" % attacks_str)
        supported_str = ",".join([
            attack
            for attack in
            handlers.connection.handlers.map])
        self.socket.sendall("Supported-Attacks: %s\n" % supported_str)
        data = self.info.get("Data-Attacks", self.server.default_data)
        data_str = ",".join([attack.name for attack in data])
        self.socket.sendall("Data-Attacks: %s\n" % data_str)
        supported_data = ",".join([
            attack
            for attack in handlers.data.handlers.map])
        self.socket.sendall("Supported-Data-Attacks: %s\n" % supported_data)
        self.socket.sendall("\n")

    def _parse_headers(self, lines):
        raw_headers = [line.split(":", 1) for line in lines[1:]]
        headers = {entry.strip(): header.strip()
                   for entry, header in raw_headers}

        client_info = {}
        # Platform-Info is required, fail if not present
        client_info["Platform-Info"] = headers["Platform-Info"]
        # Everything else is optional
        if "Installation-ID" in headers:
            client_info["Installation-ID"] = headers["Installation-ID"]

        if "Attack-Probability" in headers:
            value = float(headers["Attack-Probability"])
            if value < 0 or value > 1.0:
                raise ValueError("Attack-Probability outside range")
            client_info["Attack-Probability"] = value

        if "Attacks" in headers:
            attacks = headers["Attacks"].split(",")
            attacks = map(str.strip, attacks)
            client_info["Attacks"] = preconditions.filter_preconditions([
                    handlers.connection.handlers.map[attack] for attack in attacks
                    if attack in handlers.connection.handlers.map])

        if "Data-Attacks" in headers:
            attacks = headers["Data-Attacks"].split(",")
            attacks = map(str.strip, attacks)
            client_info["Data-Attacks"] = preconditions.filter_preconditions(
                    [handlers.data.handlers.map[attack]
                    for attack in attacks
                    if attack in
                    handlers.data.handlers.map])

        # Store the raw headers as well in case a handler needs something the
        # client sent in an additional header
        client_info["headers"] = headers

        self.info = client_info

    def _response_select_fn(self):
        try:
            data = self.socket.recv(8192)
        except socket.error:
            self.logger.info("Blame: Erorr reading from client %s.", self.address)
            return False

        if not data:
            self.logger.info("Blame: Client %s closed connection", self.address)
            return False
        data = self._buffer + data
        while "\n" in data:
            line, rest = data.split("\n", 1)
            self._handle_client_line(line)
            data = rest
        self._buffer = data
        return True

    def _handle_client_line(self, line):
        # A response is either "id <response>\n" or "id\n" if the command failed.
        words = line.strip().split(" ")
        txid = int(words[0])
        data = " ".join(words[1:])
        callback = self.queries.get(txid)
        if callback:
            del self.queries[txid]
            callback.fn(True, data)
        else:
            self.logger.debug("Blame: Response for unknown txid %d from %s", txid, self.address)


class Server:
    """Server for managing connections to the connection blaming app on devices."""
    port = None
    clients = None

    def __init__(self, port, cert, default_prob, default_attacks, default_data):
        self.txid = 0
        self.kill = False
        self.port = port
        self.cert = cert
        self.default_prob = default_prob
        self.default_attacks = default_attacks
        self.default_data = default_data
        self.clients = {}
        self.fd_map = {}
        self.logger = logging.getLogger("nogotofail.mitm")
        self.server_socket = None

    def start_listening(self):
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("", self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(2)
        if self.cert:
            self.server_socket = (
                ssl.wrap_socket(
                    self.server_socket, certfile=self.cert,
                    server_side=True,
                    do_handshake_on_connect=False))

    def _on_server_socket_select(self):
        try:
            (client_socket, client_address) = self.server_socket.accept()
        except socket.error:
            # In a wrapped SSL socket accept() can raise exceptions, if we get
            # one the client connection is broken so do nothing.
            return
        client_addr, client_port = client_address
        self.logger.debug("Blame: Connection from %s:%d", client_addr, client_port)

        old_client = self.clients.get(client_addr, None)
        if old_client:
            self.remove_client(client_address)
        self.fd_map[client_socket] = client_addr
        self.clients[client_addr] = Client(client_socket, self)

    def _on_socket_select(self, sock):
        if sock is self.server_socket:
            self._on_server_socket_select()
            return
        client_addr = self.fd_map[sock]
        client = self.clients[client_addr]
        if not client.on_select():
            self.remove_client(client_addr)

    def client_available(self, client_addr):
        """Returns if the app blame client is running on client_addr.

        This is best effort only, it may return True for lost clients.
        """
        return client_addr in self.clients and self.clients[client_addr].available

    def get_applications_async(
            self, client_addr, client_port, server_addr, server_port, callback, timeout=10):
        """Fetch the application information for a given connection tuple calling a callback when
        the response is received.
        Returns if the request was sent to the client.
        NOTE: If False is returned the callback will never be called.

        Arguments:
        client_addr -- the client ip address to query
        client_port -- the source port on the client
        server_addr -- the destination ip address as seen by the client
        server_port -- the destination port as seen by the client
        callback -- function to call when data is ready, should be of the form
                    def fn(success, platform_info=None, applications=None)
        timeout --  timeout for the request"""
        if not self.client_available(client_addr):
            return False
        if not self.clients[client_addr].get_applications_async(client_port,
                server_addr, server_port, callback, timeout):
            self.remove_client(client_addr)
            return False
        return True


    def vuln_notify_async(self, client_addr, server_addr, server_port, id,
            type, applications, callback, timeout=10):
        """Send a notification to client_addr of a vulnerability in applications.
        Returns if the notification was sent successfully

        Arguments:
            client_addr -- Client to notify
            server_addr -- remote destination of the vulnerable connection
            server_port -- remote port of the vulnerable connection
            id -- An opaque blob to identify the connection later on
            type -- Type of vuln. See nogotofail.mitm.util.vuln.*
            applications -- List of Applications to blame
            callback -- Function to call when a response is received. Should be of the form:
                def callback(success, result=False)
                    success -- If the client responded to the notification
                    result -- If the client showed the vulnerability
        """

        if not self.client_available(client_addr):
            return False
        result = self.clients[client_addr].vuln_notify_async(server_addr, server_port,
                id, type, applications, callback, timeout)
        if not result:
            self.remove_client(client_addr)
        return result

    def remove_client(self, client_addr):
        """Remove and close a blame client."""
        if client_addr not in self.clients:
            return
        client = self.clients[client_addr]
        del self.clients[client_addr]
        del self.fd_map[client.socket]
        client.close()

    def check_timeouts(self):
        """Check the timeouts on all clients and remove those that have timed out."""
        for client_addr in self.clients.keys():
            if not self.clients[client_addr].check_timeouts():
                self.logger.info("Blame: Client %s timed out", client_addr)
                self.remove_client(client_addr)

    @property
    def select_fds(self):
        """Returns the tuple of r,w,x fds to be sent to select."""
        return (set([client.socket for client in self.clients.values()] + [self.server_socket])
                , set(), set())

    def on_select(self, r, w, x):
        """Called whith the results of select.select. Note that all r,w,x is a subset of the values
        provided by select_fds."""
        for fd in set(r + w + x):
            self._on_socket_select(fd)

    def shutdown(self):
        """Shutdown the Blame server. The server should not be used after this point."""
        self.server_socket.close()
        for client in self.clients.values():
            try:
                client.close()
            except:
                pass
