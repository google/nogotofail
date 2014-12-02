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
from nogotofail.mitm.connection import RedirectConnection
from nogotofail.mitm.connection.handlers.selector import default_connection_selector, default_ssl_connection_selector, default_data_selector
from nogotofail.mitm import util

import threading
import socket
import select
import os
import sys
import logging
import time

class Server:
    """Server for handling creation and management of nogotofail.mitm.connection.Connections
    """

    def __init__(self, port, app_blame, connection_class=RedirectConnection,
                 handler_selector=default_connection_selector,
                 ssl_handler_selector=default_ssl_connection_selector,
                 data_handler_selector=default_data_selector,
                 block_non_clients=False, ipv6=False):
        self.kill = False
        self.port = port
        self.kill_fd, self.control_fd = self.setup_control_pipe()
        self.read_fds = set([self.kill_fd])
        self.write_fds = set()
        self.ex_fds = set()
        self.fds = {}
        self.connections = {}
        self.connection_class = connection_class
        self.handler_selector = handler_selector
        self.ssl_handler_selector = ssl_handler_selector
        self.data_handler_selector = data_handler_selector
        self.serving_thread = threading.Thread(target=self.run)
        self.serving_thread.daemon = True
        self.app_blame = app_blame
        self.logger = logging.getLogger("nogotofail.mitm")
        self.block_non_clients = block_non_clients
        self.ipv6 = ipv6

    def start(self):
        self.serving_thread.start()

    def run(self):
        try:
            self.serve()
        except Exception as e:
            self.logger.exception("Uncaught exception in serving thread!")
            self.logger.critical("EXITING")
            sys.exit()

    def _create_server_sockets(self):
        sockets = []
        for family in [socket.AF_INET, socket.AF_INET6]:
            if family == socket.AF_INET6 and not self.ipv6:
                break
            local_server_socket = socket.socket(family=family)
            if family == socket.AF_INET6:
                # Force into ipv6 only mode. We will bind a v4 and v6 socket.
                # This makes compat a little easier
                local_server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            local_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.connection_class.setup_server_socket(local_server_socket)
            local_server_socket.bind(("", self.port))
            local_server_socket.listen(5)
            sockets.append(local_server_socket)
        return sockets

    def serve(self):
        last_reap = time.time()

        # set up the listening sockets
        local_server_sockets = self._create_server_sockets()
        for sock in local_server_sockets:
            self.read_fds.add(sock)

        while not self.kill:
            r, w, x = select.select(self.read_fds,
                    self.write_fds,
                    self.ex_fds,
                    10)
            for fd in r + w + x:
                if fd == self.kill_fd:
                    return
                if fd in local_server_sockets:
                    client_socket, client_address = None, (None, None)
                    try:
                        (client_socket, client_address) = (
                            fd.accept())
                        self.setup_connection(client_socket)
                    except socket.error as e:
                        self.logger.error(
                            "Socket error in connection startup from %s" % client_address[0])
                        self.logger.exception(e)
                        util.close_quietly(client_socket)
                    continue
                try:
                    conn = self.connections[fd]
                except KeyError:
                    # fd could have already been removed if the other end of the socket closed
                    # and was handled before fd. fd has already been handled so
                    # move along
                    continue
                try:
                    cont = conn.bridge(fd)
                    if not cont:
                        self.remove(conn)
                except Exception as e:
                    self.logger.exception(e)
                    self.remove(conn)

            # If nothing is happening and we haven't reaped in a while reap
            now = time.time()
            if (len(r) == 0 and now - last_reap > 600) or now - last_reap > 3600:
                for conn in set(self.connections.values()):
                    if not isinstance(conn, self.connection_class):
                        continue
                    if now - conn.last_used > 3600:
                        self.remove(conn)

    def _remove_fds(self, connection):
        if connection in self.fds:
            r, w, x = self.fds[connection]
            for fd in r:
                self.read_fds.remove(fd)
                self.connections.pop(fd)
            for fd in w:
                self.write_fds.remove(fd)
                self.connections.pop(fd)
            for fd in x:
                self.ex_fds.remove(fd)
                self.connections.pop(fd)

            del self.fds[connection]

    def remove(self, connection):
        connection.close(handler_initiated=False)
        self._remove_fds(connection)

    def setup_connection(self, client_socket):
        if self.block_non_clients:
            if not self.app_blame.client_available(
                client_socket.getpeername()[0]):
                self.logger.debug("Connection from non-client %s blocked",
                                  client_socket.getpeername()[0])
                client_socket.close()
                return
        connection = (
            self.connection_class(
                self, client_socket,
                self.handler_selector,
                self.ssl_handler_selector,
                self.data_handler_selector,
                self.app_blame))
        if connection.start():
            self.set_select_fds(connection)

    def setup_control_pipe(self):
        killer, controller = os.pipe()
        return killer, controller

    def shutdown(self):
        self.kill = True
        os.write(self.control_fd, "Die!")
        self.serving_thread.join(5)
        for sock in self.read_fds | self.write_fds | self.ex_fds:
            if sock != self.kill_fd:
                util.close_quietly(sock)

    def set_select_fds(self, connection):
        """Set the set of sockets for select based on connection.select_fds.

        If connection had previous fds being used those are removed and replaced with the
        current set in select_fds.
        """
        self._remove_fds(connection)
        new_fds = connection.select_fds
        self.fds[connection] = new_fds
        r, w, x = new_fds
        self.read_fds.update(r)
        self.write_fds.update(w)
        self.ex_fds.update(x)
        for fd in set(r + w + x):
            self.connections[fd] = connection
