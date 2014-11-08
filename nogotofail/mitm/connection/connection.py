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
from OpenSSL import SSL
from OpenSSL import crypto
import logging
import select
import socket
import struct
from nogotofail.mitm.util import tls, ssl2
from nogotofail.mitm.util import close_quietly
import time
import uuid


class ConnectionWrapper(object):
    """Wrapper around OpenSSL's Connection object to make recv act like socket.recv()
    """

    def __init__(self, connection):
        self._connection = connection

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def recv(self, size):
        """Wrapper around pyOpenSSL's Connection.recv
        PyOpenSSL doesn't return "" on error like socket.recv does,
        instead it throws a SSL.ZeroReturnError or (-1, "Unexpected EOF") erorrs.

        Wrap recv so we don't have to deal with that noise.
        """
        buf = ""
        try:
            buf = self._connection.recv(size)
        except SSL.SysCallError as e:
            if e.args != (-1, "Unexpected EOF"):
                raise e
        except SSL.Error as e:
            if e.args != (-1, "Unexpected EOF"):
                raise e
        except SSL.ZeroReturnError:
            pass
        return buf


def stub_verify(conn, cert, errno, errdepth, code):
    """We don't verify the server when we attempt a MiTM.
    If the client was connecting to a host with a bad cert
    we still want to connect and MiTM them.

    Hypothetically someone could MiTM our MiTM and intercept what we intercept,
    use caution in what data you send through a MiTM'd connection if you don't trust
    the rest of your path to the real endpoint.
    """
    return True


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
    raw_client_socket = None
    client_addr, client_port = None, None
    server_socket = None
    raw_server_socket = None
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

    SSL_TIMEOUT = 2

    def __init__(
        self, server, client_socket, handler_selector,
        ssl_handler_selector, data_handler_selector, app_blame):
        self.id = uuid.uuid4()
        self.client_addr, self.client_port = client_socket.getpeername()[:2]
        self.server = server
        self.app_blame = app_blame
        self.ssl_handler_selector = ssl_handler_selector
        self.client_socket = client_socket
        self.raw_client_socket = client_socket
        self.logger = logging.getLogger("nogotofail.mitm")
        self.last_used = time.time()
        self.handler = handler_selector(self, app_blame)(self)
        data_handler_classes = data_handler_selector(self, app_blame)
        self.data_handlers = [handler_class(self)
                              for handler_class in data_handler_classes]

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

    def connect_ssl(self, client_hello):
        """Sets up both ends of SSL termination.

        Note that client_socket MUST have the TLS ClientHello as the first thing
        recv() returns
        or else pyOpenSSL will bail.

        Returns setup success.
        """
        server_name = client_hello.extensions.get("server_name")
        if server_name:
            server_name = server_name.data
            self.hostname = server_name

        try:
            # Send our own client hello to the other side
            self._setup_server_connection(server_name)

            server_cert = self.server_socket.get_peer_certificate()
            handler_cert = self.handler.on_certificate(server_cert)
            ciphers_list = self.handler.on_server_cipher_suites(client_hello)

            context = SSL.Context(SSL.SSLv23_METHOD)
            context.set_verify(SSL.VERIFY_NONE, stub_verify)
            if ciphers_list is not None:
                context.set_cipher_list(ciphers_list)
            if handler_cert is not None:
                context.use_certificate_chain_file(handler_cert)
                context.use_privatekey_file(handler_cert)

            # Required for anonymous/ephemeral DH cipher suites
            context.load_tmp_dh("./dhparam")

            # Required for anonymous/ephemeral ECDH cipher suites
            # The API is not available in the old version of pyOpenSSL which we
            # currently use. Without the code below, anonymous and ephemeral
            # ECDH cipher suites will not be used.
            if hasattr(context, "set_tmp_ecdh"):
                curve = crypto.get_elliptic_curve("prime256v1")
                context.set_tmp_ecdh(curve)

            # Send our ServerHello to the Client. Note that the Client's ClientHello
            # MUST be the first thing that self.client_socket.recv() returns
            self.client_socket.setblocking(False)
            connection = SSL.Connection(context, self.client_socket)
            connection.set_accept_state()
            self._do_ssl_handshake(connection)

            self.client_socket.setblocking(True)
            self.client_socket = ConnectionWrapper(connection)
            # Let the server know our sockets have changed
            self.server.update_sockets(self)

        except SSL.Error as e:
            self.handler.on_ssl_error(e)
            return False

        self.handler.on_ssl_establish()
        self.ssl = True
        return True

    def _setup_server_connection(self, servername=None):
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_NONE, stub_verify)
        self.server_socket.setblocking(False)
        connection = SSL.Connection(context, self.server_socket)
        if servername:
            connection.set_tlsext_host_name(servername)
        connection.set_connect_state()
        self._do_ssl_handshake(connection)

        self.server_socket.setblocking(True)
        # OpenSSL connections are socket like, so we can use them as if they
        # were a socket(once wrapped for compat)
        self.server_socket = ConnectionWrapper(connection)

    def _do_ssl_handshake(self, connection):
        start = time.time()
        while True:
            try:
                connection.do_handshake()
                break
            except (SSL.WantReadError, SSL.WantWriteError):
                now = time.time()
                if now - start > BaseConnection.SSL_TIMEOUT:
                    raise socket.timeout
                remaining = BaseConnection.SSL_TIMEOUT - (now - start)
                r, w, x = select.select(
                    [connection], [connection], [], remaining)
                if not r and not w:
                    raise socket.timeout

    def bridge(self, sock):
        """Handle bridging data from sock to the other party.

        Returns if the connection should continue.
        """
        self.last_used = time.time()
        if (sock == self.client_socket):
            return self._bridge_client()
        else:
            return self._bridge_server()

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
        close_quietly(self.raw_client_socket)
        close_quietly(self.raw_server_socket)

        self.handler.on_close(handler_initiated)
        for handler in self.data_handlers:
            handler.on_close(handler_initiated)


    def _check_for_ssl(self, client_request):
        """ Check for a client_hello in client_request and handle setting up handlers and any mitm.

        Returns if client_request was used(and should not be sent to the server)
        """
        # check for a TLS Client Hello
        record = tls.parse_tls(client_request)
        client_hello = None
        if record:
            first = record.messages[0]
            if isinstance(first, tls.types.HandshakeMessage)\
               and isinstance(first.obj, tls.types.ClientHello):
                client_hello = first.obj
        else:
           # Check for an SSLv2 Client Hello
           record = ssl2.parse_ssl2(client_request)
           if record and isinstance(record.message.obj, ssl2.types.ClientHello):
               client_hello = record.message.obj

        if not client_hello:
            return False
        return self._handle_hello(client_hello)

    def _handle_hello(self, client_hello):
        """ Handles the changing of handlers on a TLS client hello and optional mitm

        Returns if a MiTM was created
        """
        # Check for a server name and set our hostname
        if not self.hostname:
            server_name = client_hello.extensions.get("server_name")
            if server_name:
                server_name = server_name.data
                self.hostname = server_name

        # Swap to a new handler if needed.
        handler_class = self.ssl_handler_selector(
            self, client_hello, self.app_blame)
        if handler_class:
            handler = handler_class(self)
            self.handler.on_remove()
            self.handler = handler
            self.handler.on_select()

        # Check if we should start mitming this connection
        should_mitm = self.handler.on_ssl(client_hello)
        if should_mitm:
            self.connect_ssl(client_hello)
            return True
        return False

    def _bridge_client(self):
        try:
            # Check for a TLS client hello we might need to intercept
            if not self.ssl:
                client_request = self.client_socket.recv(65536, socket.MSG_PEEK)
                if not client_request:
                    return False
                # If a MiTM was attempted discard client_request, we used it
                # for establishing a MiTM with the client.
                if self._check_for_ssl(client_request):
                    return not self.closed

            client_request = self.client_socket.recv(65536)
            if not client_request:
                return False
            client_request = self.handler.on_request(client_request)
            for handler in self.data_handlers:
                client_request = handler.on_request(client_request)
                if client_request == "":
                    return not self.closed
            self.server_socket.sendall(client_request)

        except SSL.Error as e:
            self.handler.on_ssl_error(e)
            return False
        except socket.error:
            return False
        return not self.closed

    def _bridge_server(self):
        try:
            server_response = self.server_socket.recv(65536)
            if not server_response:
                return False
            server_response = self.handler.on_response(server_response)
            for handler in self.data_handlers:
                server_response = handler.on_response(server_response)
                if server_response == "":
                    break
            self.client_socket.sendall(server_response)
        except SSL.Error as e:
            self.handler.on_ssl_error(e)
            return False
        except socket.error:
            return False
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
        if not self.app_blame:
            return None
        if self._applications or cached_only:
            return self._applications
        addr, port = self._get_client_remote_name()
        self._applications = (
            self.app_blame.get_applications(
                self.client_addr,
                self.client_port,
                addr,
                port))
        self.client_info = self.app_blame.clients.get(self.client_addr)
        return self._applications

    def vuln_notify(self, type):
        """Notify the client of the connection that a vulnerability was found.

        Arguments:
            type: A nogotofail.mitm.util.vuln.* to notify the client of.

        Returns if the client was notified successfully.
        """
        if not self.app_blame:
            return False
        applications = self.applications()
        if applications is None:
            return False
        client, apps = applications
        destination = self.hostname if self.hostname else self.server_addr
        return self.app_blame.vuln_notify(
            self.client_addr, destination, self.server_port, self.id, type,
            apps)

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

class RedirectConnection(BaseConnection):
    """Connection based on getting traffic from iptables redirect rules"""
    def start(self):
        self.server_addr, self.server_port = (
            self._get_original_dest(self.client_socket))

        self.handler.on_select()
        for handler in self.data_handlers:
            handler.on_select()
        try:
            # Python's socket.create_connection will handle the socket family correctly
            # based on server_addr
            self.server_socket = socket.create_connection((self.server_addr, self.server_port),
                    BaseConnection.SSL_TIMEOUT)
            self.raw_server_socket = self.server_socket
        except socket.error:
            return False
        self.handler.on_establish()
        for handler in self.data_handlers:
            handler.on_establish()
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
        # Try and connect to the endpoint
        try:
            self.server_socket = socket.create_connection((self.server_addr, self.server_port),
                    BaseConnection.SSL_TIMEOUT)
            self.raw_server_socket = self.server_socket
        except socket.error:
            # Send a generic connection error and bail
            self.client_socket.sendall(self._build_error_response(
                SocksConnection.RESP_NETWORK_UNREACHABLE))
            self.client_socket.close()
            return False

        # Send the OK message
        self.client_socket.sendall(self._build_response())


        # At this point the connection is ready to go
        self.handler.on_establish()
        for handler in self.data_handlers:
            handler.on_establish()
        return True

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


