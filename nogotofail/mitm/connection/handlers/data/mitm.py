r'''
Copyright 2015 Google Inc. All rights reserved.

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
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.util import tls, ssl2, extras
from nogotofail.mitm.util.tls.types import Extension
import logging
import os
import socket

class ConnectionWrapper(object):
    """Wrapper around OpenSSL's Connection object to make recv act like socket.recv() and to support MSG_PEEK
    """

    def __init__(self, connection):
        self._connection = connection
        self.buffer = ""

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def recv(self, size, flags=0):
        """Wrapper around pyOpenSSL's Connection.recv
        PyOpenSSL doesn't return "" on error like socket.recv does,
        instead it throws a SSL.ZeroReturnError or (-1, "Unexpected EOF") erorrs.

        Wrap recv so we don't have to deal with that noise.
        """
        if flags & socket.MSG_PEEK == 0:
            return self._recv(size)
        if len(self.buffer) >= size:
            return self.buffer[:size]
        try:
            self.buffer += self._recv(size-len(self.buffer))
        except SSL.WantReadError:
            pass
        return self.buffer[:size]

    def _recv(self, size):
        if size <= len(self.buffer):
            out = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return out
        buf = self.buffer
        self.buffer = ""
        size -= len(buf)
        try:
            buf += self._connection.recv(size)
        except SSL.SysCallError as e:
            if e.args != (-1, "Unexpected EOF"):
                raise e
        except SSL.ZeroReturnError:
            pass
        except SSL.WantReadError as e:
            # We may have consumed all data in a previous peek, ignore it if we have something to return.
            if not buf:
                raise e
        except SSL.Error as e:
            if e.args != (-1, "Unexpected EOF"):
                raise e
        return buf


def _stub_verify(conn, cert, errno, errdepth, code):
    """We don't verify the server when we attempt a MiTM.
    If the client was connecting to a host with a bad cert
    we still want to connect and MiTM them.

    Hypothetically someone could MiTM our MiTM and intercept what we intercept,
    use caution in what data you send through a MiTM'd connection if you don't trust
    the rest of your path to the real endpoint.
    """
    return True

@handler(handlers, internal=True)
class SslMitmHandler(DataHandler):
    name = "_sslmitm"
    description = "Detect SSL establishing on the wire and potentially start a MiTM"
    _peek_request_fn = None
    _peek_response_fn = None

    def peek_request(self, request):
        if self._peek_request_fn:
            # request here isn't used because during the handshake it will always be "".
            return self._peek_request_fn()
        return self._check_for_ssl(request)

    def peek_response(self, response):
        if self._peek_response_fn:
            # Same as in peek_request.
            return self._peek_response_fn()
        return False

    def _peek_established(self):
        """Peek function for when the MiTM is completed and peeking is no longer required.
        """
        return False

    def _gen_ssl_connect_fn(self, connection, post_fn):
        """Generate a bridge_fn for doing an ssl handshake on connection.
        Once the handshake is completed post_fn will be called
        """
        def do_ssl_handshake():
            try:
                connection.do_handshake()
                return post_fn()
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
            except SSL.Error as e:
                self.connection.handler.on_ssl_error(e)
                return False
            except socket.error as e:
                return False
            return True
        return do_ssl_handshake

    def start_ssl_mitm(self, client_hello):
        """Start the SSL MiTM.
        This is non-blocking and will set the bridge_fns and select_fds as follows:
        1. Start the SSL handshake with the server, ignore client data
        2. On handshake completion call _on_server_ssl_established
        3. Start the SSL handshake with the client, ignore server data
        4. On completion call _on_client_ssl_established
        5. At this point the SSL MiTM is set up and we switch back to bridging mode
        """
        self.client_hello = client_hello
        server_name = client_hello.extensions.get(Extension.TYPE.SERVER_NAME)
        if server_name:
            server_name = server_name.data
            self.connection.hostname = server_name
        self._start_server_ssl_connection(server_name)

    def _start_server_ssl_connection(self, servername=None):
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_NONE, _stub_verify)
        connection = SSL.Connection(context, self.connection.server_socket)
        self.connection.server_socket = (ConnectionWrapper(connection))
        if servername:
            connection.set_tlsext_host_name(servername)
        connection.set_connect_state()
        self._peek_response_fn = self._gen_ssl_connect_fn(connection,
                self._on_server_ssl_established)
        connection.set_connect_state()
        # Stop selecting on the client until we are connected
        self.connection.set_select_fds(rlist=[self.connection.server_socket])
        # Start the handshake
        self._peek_response_fn()


    def _start_client_ssl_connection(self):
        server_cert = self.connection.server_socket.get_peer_certificate()
        handler_cert = self.connection.handler.on_certificate(server_cert)
        ciphers_list = self.connection.handler.on_server_cipher_suites(self.client_hello)

        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_verify(SSL.VERIFY_NONE, _stub_verify)
        if ciphers_list is not None:
            context.set_cipher_list(ciphers_list)
        if handler_cert is not None:
            context.use_certificate_chain_file(handler_cert)
            context.use_privatekey_file(handler_cert)

        # Required for anonymous/ephemeral DH cipher suites
        params_path = extras.get_extras_path("./dhparam")
        if os.path.exists(params_path):
            context.load_tmp_dh(extras.get_extras_path("./dhparam"))
        else:
            self.log(logging.WARNING, "Required file dhparam not found, anonymous/ephemeral DH cipher suites may not work")

        # Required for anonymous/ephemeral ECDH cipher suites
        # The API is not available in the old version of pyOpenSSL which we
        # currently use. Without the code below, anonymous and ephemeral
        # ECDH cipher suites will not be used.
        if hasattr(context, "set_tmp_ecdh"):
            curve = crypto.get_elliptic_curve("prime256v1")
            context.set_tmp_ecdh(curve)

        # Send our ServerHello to the Client.
        connection = SSL.Connection(context, self.connection.client_socket)
        connection.set_accept_state()
        self.connection.client_socket = (ConnectionWrapper(connection))
        self._peek_request_fn = self._gen_ssl_connect_fn(connection,
                self._on_client_ssl_established)
        # Only listen for client events until the connection is established
        self.connection.set_select_fds(rlist=[self.connection.client_socket])
        # Start the handshake
        self._peek_request_fn()

    def _on_server_ssl_established(self):
        """Once the server is connected begin connecting the client"""
        self._peek_response_fn = self._peek_established
        # Start Setting up the client connection
        self._start_client_ssl_connection()
        return True

    def _on_client_ssl_established(self):
        """Once the client is connected return to bridging mode"""
        self._peek_request_fn = self._peek_established
        # Now we are ready to bridge in both directions
        self.connection.set_select_fds(rlist=[self.connection.client_socket,
                                       self.connection.server_socket])
        self.connection.handler.on_ssl_establish()
        return True

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
        if not self.connection.hostname:
            server_name = client_hello.extensions.get(Extension.TYPE.SERVER_NAME)
            if server_name:
                server_name = server_name.data
                self.connection.hostname = server_name

        # Swap to a new handler if needed.
        handler_class = self.connection.ssl_handler_selector(
            self.connection, client_hello, self.connection.app_blame)
        if handler_class:
            self.connection.replace_connection_handler(handler_class)

        # Check if we should start mitming this connection
        should_mitm = self.connection.handler.on_ssl(client_hello)
        # Call all the data handler's on_ssl so they can do any analysis they
        # need.
        for handler in self.connection.data_handlers:
            handler.on_ssl(client_hello)
        if should_mitm:
            self.start_ssl_mitm(client_hello)
            return True
        return False
