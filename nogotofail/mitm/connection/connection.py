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
import errno
import logging
import os
import select
import socket
import struct
import time
import uuid
from OpenSSL import SSL
from nogotofail.mitm.util import close_quietly, extras

class BaseConnection(object):
    """Handles the creation and bridging of both sides of the network connection
    and passing data and events to the handler provided by handler_selector.

    Depending on handler.proxy the connection can act as a simple pass through
    proxy or as an SSL terminator.

    Connections should subclass this and implement start and _get_client_remote_name
    in order to set up the remote socket correctly.
    """

    handler = None
    data_handlers = []
    ssl_handler_selector = None
    client_socket = None
    client_addr, client_port = None, None
    server_socket = None
    server_addr, server_port = None, None
    server_cert_path = None
    app_blame = None
    _applications = None
    logger = None
    server = None
    ssl = False
    last_used = None
    id = None
    hostname = None
    closed = False
    client_info = None
    select_fds = [], [], []
    _connected = False
    _blame_in_progress = False

    def __init__(
        self, server, client_socket, handler_selector,
        ssl_handler_selector, data_handler_selector, app_blame):
        self.id = uuid.uuid4()
        self.client_addr, self.client_port = client_socket.getpeername()[:2]
        self.server = server
        self.app_blame = app_blame
        self.ssl_handler_selector = ssl_handler_selector
        self.client_socket = client_socket
        # Make sure the client socket is nonblocking
        self.client_socket.setblocking(False)
        self.logger = logging.getLogger("nogotofail.mitm")
        self.last_used = time.time()
        self.handler = handler_selector(self, app_blame)(self)
        data_handler_classes = data_handler_selector(self, app_blame)
        self.data_handlers = [handler_class(self)
                              for handler_class in data_handler_classes]
        self.logger.debug("Using data handlers %s" %
                ', '.join([handler.name for handler in self.data_handlers]))

        self.client_bridge_fn = self._bridge_client
        self.server_bridge_fn = self._bridge_server

    @staticmethod
    def setup_server_socket(sock):
        """Do any additional pre-bind setup needed on the local socket.

        This can be used to set sockopts as needed"""
        pass

    def start(self):
        """Setup the remote end of the connection and client connection
        to be ready to start bridging traffic.

        This method should be implemented based on how connections are routed to nogotofail.mitm
        such as iptables redirect or proxies.

        This should call handler.on_select and handler.on_establish when appropriate
        and set server_addr and server_port to the remote endpoint's address.

        Returns if setup was successful.
        """
        raise NotImplemented()

    def set_select_fds(self, rlist=[], wlist=[], xlist=[]):
        """Set the set of fds to use for the server's select loop.

        This update self.select_fds to the new values and calls server.set_select_fds.
        """
        self.select_fds = rlist, wlist, xlist
        self.server.set_select_fds(self)

    def _on_establish(self):
        """Called when the connection to the server is established successfully"""
        self.handler.on_establish()
        for handler in self.data_handlers:
            handler.on_establish()

    def _on_server_connected(self):
        """Called when the socket.connect to the server completes"""
        self._connected = True
        self.server_bridge_fn = self._bridge_server
        self.client_bridge_fn = self._bridge_client

        # Check if the connection is now ready to be used
        if not self._blame_in_progress:
            self._on_connection_ready()
        else:
            self.set_select_fds()


    def _server_connect_bridge_fn(self):
        """Bridge callback function for non-blocking socket connects

        This should be set as the server_bridge_fn before calling socket.connect
        on a non-blocking server_socket."""
        error = self.server_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            self.logger.info("Failed to connect to endpoint %s:%s errno %s",
                    self.server_addr, self.server_port, error)
            return False

        self._on_server_connected()
        return True

    def _start_server_connect_nonblocking(self):
        """Setup the server socket and start a nonblocking connect"""
        try:
            # Start the blame request

            addr, port = self._get_client_remote_name()
            self._blame_in_progress = self.app_blame.get_applications_async(self.client_addr,
                    self.client_port, addr, port, self._on_get_applications_result)

            self.server_socket = socket.socket(self.client_socket.family,
                    self.client_socket.type,
                    self.client_socket.proto)
            self.server_socket.setblocking(False)
            self.server_bridge_fn = self._server_connect_bridge_fn
            # We don't want to handle any data from the client until the
            # connection to the server is established, only listen to the server
            # socket for now.
            self.set_select_fds(wlist=[self.server_socket])
            # Try and connect, this will probably raise an EINPROGRESS
            self.server_socket.connect((self.server_addr, self.server_port))
            # If we finished instantly call _on_server_connected()
            self._on_server_connected()
        except socket.error as e:
            # We expect an EINPROGRESS from the connect call.
            if e.errno != errno.EINPROGRESS:
                raise e

    def bridge(self, sock):
        """Handle bridging data from sock to the other party.

        Returns if the connection should continue.
        """
        self.last_used = time.time()
        if (sock == self.client_socket):
            return self.client_bridge_fn()
        elif sock == self.server_socket:
            return self.server_bridge_fn()

    def close(self, handler_initiated=True):
        """Close the connection. Does nothing if the connection is already closed.

        handler_initiated: If a handler is requesting a close versus the connection
        being closed by one of the endpoints.
        """
        if self.closed:
            return
        self.closed = True

        close_quietly(self.server_socket)
        close_quietly(self.client_socket)

        self.handler.on_close(handler_initiated)
        for handler in self.data_handlers:
            handler.on_close(handler_initiated)

    def _bridge_client(self):
        try:
            try:
                client_request = self.client_socket.recv(65536, socket.MSG_PEEK)
                handled = self.handler.peek_request(client_request)
                if handled:
                    return not self.closed
                for handler in self.data_handlers:
                    if handler.peek_request(client_request):
                        return not self.closed
                client_request = self.client_socket.recv(65536)
            except (socket.error, SSL.WantReadError):
                # recv can still time out even if select returned this socket
                # for reading if we are using a wrapped SSL socket and no
                # application data was ready. Keep bridging.
                return not self.closed
            if not client_request:
                return False
            client_request = self.handler.on_request(client_request)
            for handler in self.data_handlers:
                client_request = handler.on_request(client_request)
                if client_request == "":
                    return not self.closed
            sent = self.server_socket.send(client_request)

            # send returning a 0 means the connection has been broken.
            if sent == 0:
                return False
            # Check and make sure we sent everything, otherwise we need to start
            # handling a full send buffer.
            if sent != len(client_request):
                remaining = client_request[sent:]
                self._handle_short_server_send(remaining)

        except SSL.Error as e:
            self.handler.on_ssl_error(e)
            return False
        except socket.error:
            return False
        return not self.closed

    def _bridge_server(self):
        try:
            try:
                server_response = self.server_socket.recv(65536, socket.MSG_PEEK)
                handled = self.handler.peek_response(server_response)
                if handled:
                    return not self.closed
                for handler in self.data_handlers:
                    if handler.peek_response(server_response):
                        return not self.closed
                server_response = self.server_socket.recv(65536)
            except (socket.error, SSL.WantReadError):
                # recv can still time out even if select returned this socket
                # for reading if we are using a wrapped SSL socket and no
                # application data was ready. Keep bridging.
                return not self.closed
            if not server_response:
                return False
            server_response = self.handler.on_response(server_response)
            for handler in self.data_handlers:
                server_response = handler.on_response(server_response)
                if server_response == "":
                    return not self.closed
            sent = self.client_socket.send(server_response)
            # send returning a 0 means the connection has been broken.
            if sent == 0:
                return False
            # Check and make sure we sent everything, otherwise we need to start
            # handling a full send buffer.
            if sent != len(server_response):
                remaining = server_response[sent:]
                self._handle_short_client_send(remaining)
        except SSL.Error as e:
            self.handler.on_ssl_error(e)
            return False
        except socket.error:
            return False
        return not self.closed

    def _handle_short_client_send(self, remaining):
        """Handle a send to the client that failed to send all the data.
        This means our send buffer is full so start selecting for W on the client and stop
        reading data from the server until we've successfully sent everything pending."""
        self._remaining_client_send_data = remaining
        self.set_select_fds(wlist=[self.client_socket])
        self.client_bridge_fn = self._short_send_client_bridge_fn

    def _short_send_client_bridge_fn(self):
        data = self._remaining_client_send_data
        try:
            sent = self.client_socket.send(data)
        except socket.error:
            return False
        remaining = data[sent:]
        self._remaining_client_send_data = remaining
        # Keep sending if we're not done yet
        if remaining:
            return not self.closed
        # Otherwise resume normal operations
        self.client_bridge_fn = self._bridge_client
        self.set_select_fds(rlist=[self.client_socket, self.server_socket])
        return not self.closed

#TODO: Having a method for short_client_send and short_server_send is just code waste, there
# should just be one
    def _handle_short_server_send(self, remaining):
        """Handle a send to the client that failed to send all the data.
        This means our send buffer is full so start selecting for W on the client and stop
        reading data from the server until we've successfully sent everything pending."""
        self._remaining_server_send_data = remaining
        self.set_select_fds(wlist=[self.server_socket])
        self.server_bridge_fn = self._short_send_server_bridge_fn

    def _short_send_server_bridge_fn(self):
        data = self._remaining_server_send_data
        try:
            sent = self.server_socket.send(data)
        except socket.error:
            return False
        remaining = data[sent:]
        self._remaining_server_send_data = remaining
        # Keep sending if we're not done yet
        if remaining:
            return not self.closed
        # Otherwise resume normal operations
        self.server_bridge_fn = self._bridge_server
        self.set_select_fds(rlist=[self.client_socket, self.server_socket])
        return not self.closed

    def _get_client_remote_name(self):
        """Get the addr, port of the what the client thinks is their remote
        This is used for blame, so this should correspond to some tcp connection
        on the client
        """
        raise NotImplemented()

    def applications(self, cached_only=False):
        """Returns the result of nogotofail.mitm.blame.Server.get_applications on demand
        with caching to avoid needless delays.

        See the docs for nogotofail.mitm.blame.Server.get_applications more information.
        """
        return self._applications

    def vuln_notify(self, type):
        """Notify the client of the connection that a vulnerability was found.

        Arguments:
            type: A nogotofail.mitm.util.vuln.* to notify the client of.

        Returns if the client was notified successfully.
        """
        if not self.app_blame:
            return False
        if self._applications is None:
            return False
        info, apps = self._applications
        destination = self.hostname if self.hostname else self.server_addr

        return self.app_blame.vuln_notify_async(
            self.client_addr, destination, self.server_port, self.id, type,
            apps, self._on_vuln_notify_result)

    def _on_vuln_notify_result(self, success, result=False):
        # TODO: do something if vuln notify fails?
        pass

    def _on_get_applications_result(self, success, info=None, applications=None):
        self._blame_in_progress = False
        if success:
            self._applications = info, applications
            self.client_info = self.app_blame.clients[self.client_addr]
        if self._connected:
            self._on_connection_ready()

    def _on_connection_ready(self):
        self._on_establish()
        self.set_select_fds(rlist=[self.client_socket, self.server_socket])

    def inject_request(self, request):
        """Inject a request to the server.
        """
        request = self.handler.on_inject_request(request)
        for handler in self.data_handlers:
            request = handler.on_inject_request(request)
            if request == "":
                break
        self.server_socket.sendall(request)

    def inject_response(self, response):
        """Inject a response to the client.
        """
        response = self.handler.on_inject_response(response)
        for handler in self.data_handlers:
            response = handler.on_inject_response(response)
            if response == "":
                break
        self.client_socket.sendall(response)

    def replace_connection_handler(self, new_handler_class):
            handler = new_handler_class(self)
            self.handler.on_remove()
            self.handler = handler
            self.handler.on_select()

class RedirectConnection(BaseConnection):
    """Connection based on getting traffic from iptables redirect rules"""

    def start(self):
        self.server_addr, self.server_port = (
            self._get_original_dest(self.client_socket))

        # If the client tries to connect to the MiTM through the MiTM it will
        # lead to a loop where we make a connection to ourselves which is then
        # MiTM'd and then tries to connect to the MiTM and so on until we run
        # out of fd's and the whole thing comes crashing down, try and avoid
        # that.
        if self.server.is_remote_mitm_server(self.server_addr, self.server_port):
            self.logger.warning(
                "Client %s attempting to connect to MiTM directly, aborting connection." %
                (self.client_addr))
            close_quietly(self.client_socket)
            return False

        self.handler.on_select()
        for handler in self.data_handlers:
            handler.on_select()
        try:
            self._start_server_connect_nonblocking()
        except socket.error:
            return False
        return True

    def _get_original_dest(self, sock):
        SO_ORIGINAL_DST = 80
        dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 28)
        family = struct.unpack_from("H", dst)[0]
        # Parse the raw_ip and raw port from the struct sockaddr_in/in6
        if family == socket.AF_INET:
            raw_port, raw_ip = struct.unpack_from("!2xH4s", dst)
        elif family == socket.AF_INET6:
            raw_port, raw_ip = struct.unpack_from("!2xH4x16s", dst)
        else:
            raise ValueError("Unsupported sa_family_t %d" % family)
        return socket.inet_ntop(family, raw_ip), int(raw_port)

    def _get_client_remote_name(self):
        return self.server_addr, self.server_port

class TproxyConnection(RedirectConnection):
    """Connection based on getting traffic from iptables TPROXY"""

    @staticmethod
    def setup_server_socket(sock):
        # Required for Tproxy mode
        IP_TRANSPARENT = 19
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)

    def _get_client_remote_name(self):
        return self.server_addr, self.server_port

    def _get_original_dest(self, sock):
        # In tproxy the socket's name is that of the remote endpoint
        return sock.getsockname()[:2]

class SocksConnection(BaseConnection):
    """Connection that acts as a socks proxy for connection setup"""

    SOCKS_CONNECT = 0x01

    ATYPE_IP = 0x01
    ATYPE_DNS = 0x03
    ATYPE_IP6 = 0x04

    RESP_SUCCESS = 0x00
    RESP_GENERAL_ERROR = 0x01
    RESP_NETWORK_UNREACHABLE = 0x03
    RESP_COMMAND_UNSUPPORTED = 0x07

    def _get_client_remote_name(self):
        return self.client_remote_addr, self.client_remote_port

    def start(self):
        # Save the remote used for blaming
        self.client_remote_addr, self.client_remote_port = self.client_socket.getsockname()[:2]

        # Do the handshake to get the destination
        self.client_socket.settimeout(1)
        try:
            self.server_addr, self.server_port = (
                self._get_original_dest(self.client_socket))
        except (ValueError, struct.error, socket.error) as e:
            self.client_socket.close()
            return False

        self.handler.on_select()
        for handler in self.data_handlers:
            handler.on_select()
        # Start the connection to the endpoint
        try:
            self._start_server_connect_nonblocking()
        except socket.error:
            # Send a generic connection error and bail
            self.client_socket.sendall(self._build_error_response(
                SocksConnection.RESP_NETWORK_UNREACHABLE))
            self.close()
            return False

        return True

    def _on_server_connected(self):
        try:
            self.client_socket.sendall(self._build_response())
        except socket.error:
            self.client_socket.sendall(self._build_error_response(
                SocksConnection.RESP_NETWORK_UNREACHABLE))
            self.close()

        super(SocksConnection, self)._on_server_connected()


    def _build_response(self):
        """Build the OK SOCKS5 connection response"""
        addr, port = self.client_socket.getsockname()[:2]
        family = self.client_socket.family
        addr_str = socket.inet_pton(family, addr)
        if family == socket.AF_INET:
            atype = chr(SocksConnection.ATYPE_IP)
        elif family == socket.AF_INET6:
            atype = chr(SocksConnection.ATYPE_IP6)
        else:
            raise ValueError("Bad socket family")
        return ("\x05\x00\x00" + atype + addr_str +
                struct.pack("!H", port))

    def _build_error_response(self, response):
        """Build a SOCKS5 error response"""
        return "\x05" + chr(response) + "\x00\x01\x00\x00\x00\x00\x00\x00"

    def _get_original_dest(self, sock):
        """Does the SOCKS5 handshake and returns the address, port of the destination

        Can raise a socket.error, ValueError, and struct.error if the other side isn't
        speaking SOCKS5 or times out"""
        message = sock.recv(1024)
        version, nmethods = struct.unpack_from("BB", message)
        if version != 0x5:
            raise ValueError("Bad version in handshake")
        methods = struct.unpack_from("%dB" % nmethods, message, 2)
        if len(methods) != nmethods:
            raise ValueError("Methods mismatch")
        # Ingore methods, we just do unauth'd
        sock.sendall("\x05\x00")
        request = sock.recv(1024)
        ver, cmd, atype = struct.unpack_from("BBxB", request)
        if ver != 0x5:
            raise ValueError("Bad version in handshake")
        if cmd != SocksConnection.SOCKS_CONNECT:
            sock.sendall(self._build_error__response(SocksConnection.RESP_COMMAND_UNSUPPORTED))
            raise ValueError("Unsupported command")

        if atype == SocksConnection.ATYPE_IP:
            addr = request[4:8]
            addr = socket.inet_ntop(socket.AF_INET, addr)
            port = struct.unpack_from("!H", request, 8)[0]
        elif atype == SocksConnection.ATYPE_DNS:
            length = struct.unpack_from("B", request, 4)[0]
            addr = request[5:5 + length]
            port = struct.unpack_from("!H", request, 5 + length)[0]
        elif atype == SocksConnection.ATYPE_IP6:
            addr = request[4:20]
            addr = socket.inet_ntop(socket.AF_INET6, addr)
            port = struct.unpack_from("!H", request, 20)[0]
        else:
            sock.sendall(self._build_error_response(SocksConnection.RESP_GENERAL_ERROR))
            raise ValueError("Unknown ATYP")
        return addr, port


