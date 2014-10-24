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
import threading
import time
import urllib

from nogotofail.mitm.connection import handlers
Application = namedtuple("Application", ["package", "version"])


class Client(object):
    socket = None
    info = None
    last_used = None

    def __init__(self, socket, info, now):
        self.socket = socket
        self.info = info
        self.last_used = now


def recv_lines(socket):
    lines = []
    file = socket.makefile()
    while True:
        line = file.readline().strip()
        if line == "":
            break
        lines.append(line)
    return lines


class Server:
    """Server for managing connections to the connection blaming app on devices.
    """
    port = None
    clients = None
    CLIENT_TIMEOUT = 21600

    def __init__(self, port, cert, default_prob, default_attacks, default_data):
        self.txid = 0
        self.kill = False
        self.port = port
        self.cert = cert
        self.default_prob = default_prob
        self.default_attacks = default_attacks
        self.default_data = default_data
        self.clients = {}
        self.listening_thread = threading.Thread(target=self.run)
        self.listening_thread.daemon = True
        self.logger = logging.getLogger("nogotofail.mitm")
        self.server_socket = None

    def start(self):
        self.listening_thread.start()

    def run(self):
        try:
            self.listen()
        except Exception as e:
            self.logger.exception("Uncaught exception in Listening thread!")
            self.logger.critical("EXITING")
            sys.exit()

    def listen(self):
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("", self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(2)
        if self.cert:
            self.server_socket = (
                ssl.wrap_socket(
                    self.server_socket, certfile=self.cert,
                    server_side=True))
        while not self.kill:
            try:
                # Check our old sockets and cleanup if needed
                for client in self.clients.keys():
                    self.client_available(client)

                (client_socket, client_address) = self.server_socket.accept()
                client_socket.settimeout(2)
                client_addr, client_port = client_address
                client_info = None

                # handshake
                try:
                    client_info = self._handshake(client_socket)
                except (ValueError, KeyError, IndexError):
                    try:
                        client_socket.sendall("400 Error parsing message\n\n")
                    except socket.error:
                        pass
                    client_socket.close()
                    self.logger.warning(
                        "AppBlame bad handshake from %s" % client_addr)
                    continue
                except socket.timeout:
                    client_socket.close()
                    self.logger.info(
                        "AppBlame handshake timeout from %s" % client_addr)
                    continue

                old_client = self.clients.get(client_addr, None)
                self.clients[client_addr] = Client(
                    client_socket, client_info, time.time())
                if old_client:
                    old_client.socket.close()
                self.logger.info("AppBlame new client from %s" % client_addr)
            except socket.timeout:
                pass
            except socket.error:
                self.logger.exception("AppBlame socket error")
        self.server_socket.close()

    def _handshake(self, client_socket):
        lines = recv_lines(client_socket)
        name, version = lines[0].split("/", 1)
        if name != "nogotofail_ctl":
            raise ValueError("Unexpected app type")
        # Parse out the headers
        raw_headers = [line.split(":", 1) for line in lines[1:]]
        headers = {entry.strip(): header.strip()
                   for entry, header in raw_headers}

        client_info = self._parse_headers(headers)

        # Send the OK
        client_socket.sendall("0 OK\n")
        # Send the configs
        prob = client_info.get("Attack-Probability", self.default_prob)
        client_socket.sendall("Attack-Probability: %f\n" % prob)
        attacks = client_info.get("Attacks", self.default_attacks)
        attacks_str = ",".join([attack.name for attack in attacks])
        client_socket.sendall("Attacks: %s\n" % attacks_str)
        supported_str = ",".join([
            attack
            for attack in
            handlers.connection.handlers.map])
        client_socket.sendall("Supported-Attacks: %s\n" % supported_str)
        data = client_info.get("Data-Attacks", self.default_data)
        data_str = ",".join([attack.name for attack in data])
        client_socket.sendall("Data-Attacks: %s\n" % data_str)
        supported_data = ",".join([
            attack
            for attack in handlers.data.handlers.map])
        client_socket.sendall("Supported-Data-Attacks: %s\n" % supported_data)

        client_socket.sendall("\n")
        return client_info

    def _parse_headers(self, headers):
        client_info = {}
        # Platform-Info is required
        client_info["Platform-Info"] = headers["Platform-Info"]
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
            client_info["Attacks"] = [
                handlers.connection.handlers.map[attack] for attack in attacks
                if attack in handlers.connection.handlers.map]
            if len(client_info["Attacks"]) == 0:
                client_info["Attack-Probability"] = 0

        if "Data-Attacks" in headers:
            attacks = headers["Data-Attacks"].split(",")
            attacks = map(str.strip, attacks)
            client_info["Data-Attacks"] = [handlers.data.handlers.map[attack]
                                           for attack in attacks
                                           if attack in
                                           handlers.data.handlers.map]

        # Store the raw headers as well in case a handler needs something the
        # client sent in an additional header
        client_info["headers"] = headers

        return client_info

    def client_available(self, client_addr):
        """Returns if the app blame client is running on client_addr.

        This is best effort only, it may return True for lost clients.
        """
        client = self.clients.get(client_addr, None)
        if not client:
            return False
        now = time.time()
        if now - client.last_used > Server.CLIENT_TIMEOUT:
            self.logger.info("AppBlame pruning client %s", client_addr)
            del self.clients[client_addr]
            client.socket.close()
            return False

        return True

    def get_applications(
        self, client_addr, client_port, server_addr, server_port):
        """Get the list of applications that owns the (client_addr, client_port, server_addr, server_port) connection on the device.

        Returns a tuple containing the platform info string and a list of
        Application or None if the
        client is available.
        """
        if not self.client_available(client_addr):
            return None

        client = self.clients[client_addr]
        client_socket = client.socket
        client.last_used = time.time()

        txid = self.txid
        self.txid += 1

        family = socket.AF_INET6 if ":" in server_addr else socket.AF_INET

        message = (
            unicode(
                "%d tcp_client_id %s %s %s\n" %
                (txid, client_port,
                 socket.inet_pton(family, server_addr).encode("hex"),
                 server_port)))
        try:
            client_socket.sendall(message)
            response = client_socket.recv(8192)
            if response == "":
                raise ValueError("Socket closed")
            response = unicode(response).strip()
        except (socket.error, ValueError) as e:
            self.logger.info(
                "AppBlame error for %s, %s. Removing." % (client_addr, e))
            del self.clients[client_addr]
            client_socket.close()
            return None

        try:
            inid, apps = response.split(" ", 1)
        except ValueError:
            return None
        if int(inid) != txid:
            self.logger.error("Blame response for wrong txid, expected %s got %s" % (txid, inid))
            return None
        platform_info = self.clients[client_addr].info.get(
            "Platform-Info", "Unknown")
        apps = apps.split(",")
        try:
            return platform_info, [Application(
                *map(urllib.unquote, app.strip().split(" ", 1)))
                                   for app in apps]
        except (ValueError, TypeError):
            return None

    def vuln_notify(
        self, client_addr, server_addr, server_port, id, type,
        applications):
        """Send a notification to client_addr of a vulnerability in applications.

        Arguments:
            client_addr: Client to notify
            server_addr: remote destination of the vulnerable connection
            server_port: remote port of the vulnerable connection
            id: An opaque blob to identify the connection later on
            type: Type of vuln. See nogotofail.mitm.util.vuln.*
            applications: List of Applications to blame

        Returns if the notification was sent successfully
        """

        if not self.client_available(client_addr):
            return False

        client = self.clients[client_addr]
        client_socket = client.socket
        client.last_used = time.time()

        txid = self.txid
        self.txid += 1
        message = (
            unicode("%d vuln_notify %s %s %s %d %s\n") %
            (txid, id, type, server_addr, server_port,
             ", ".join(
                 [
                     "%s %s" % (urllib.quote(app.package), app.version)
                     for app in applications])))
        try:
            client_socket.sendall(message)
            response = client_socket.recv(8192)
            if response == "":
                raise ValueError("Socket closed")
            response = unicode(response).strip()
        except (socket.error, ValueError) as e:
            self.logger.info(
                "AppBlame notify error for %s, %s. Removing." %
                (client_addr, e))
            del self.clients[client_addr]
            client_socket.close()
            return False
        id, message = response.split(" ", 2)
        if int(id) != txid:
            self.logger.error("Blame response for wrong txid, expected %s got %s" % (txid, id))
            return False

        return message == "OK"

    def shutdown(self):
        self.kill = True
        self.server_socket.close()
        self.listening_thread.join(5)
        for client in self.clients.values():
            try:
                client.socket.close()
            except:
                pass
