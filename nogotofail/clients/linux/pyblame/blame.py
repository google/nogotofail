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
import collections
import glob
import os
import stat
import socket
import ssl
import sys
import uuid
import logging
import urllib

from OpenSSL import crypto
from nogotofail.clients.linux.pyblame import util

Application = collections.namedtuple("Application", ["application", "version"])
class BlameConnection(object):
    host = ""
    port = -1
    install_id = ""
    blame_sock = None
    resp_headers = {}
    probability = 0
    override_attacks = True
    attacks = []
    data_attacks = []
    platform_info = ""
    ssl = True
    fingerprint_callback = None
    vuln_callback = None
    info_callback = None
    handshake_completed = False


    def __init__(self, host, port, ssl=True, fingerprint_callback=None,
            install_id=None, platform_info="Unix", probability=None,
            attacks=None, data_attacks=None,
            vuln_callback=None, info_callback=None):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.fingerprint_callback = fingerprint_callback
        self.install_id = install_id or uuid.uuid4()
        self.platform_info = platform_info
        self.probability = probability
        self.attacks = attacks
        self.data_attacks = data_attacks
        self.vuln_callback = vuln_callback
        self.info_callback = info_callback
        self.logger = logging.getLogger("pyblame")

    def build_headers(self):
        """Create the dictionary headers to send the server in the handshake.
        """
        headers = {}
        headers["Installation-ID"] = self.install_id
        headers["Platform-Info"] = self.platform_info
        if self.attacks is not None:
            headers["Attacks"] = ",".join(self.attacks)
        if self.data_attacks is not None:
            headers["Data-Attacks"] = ",".join(self.data_attacks)
        if self.probability is not None:
            headers["Attack-Probability"] = self.probability
        return headers

    def handshake(self):
        """Do the blame handshake with the server.

        connect MUST have been called before this
        """
        if not self.blame_sock:
            raise ValueError("Connection not created before call to handshake")
        headers = self.build_headers()
        f = self.blame_sock.makefile()
        f.write("nogotofail_ctl/1.0\n" +
                "\n".join(("%s: %s" % (key, value) for key, value in headers.iteritems())) +
                "\n\n")
        f.flush()

        line = f.readline().strip()
        if line.split(" ")[0] != "0":
            raise ValueError("Server rejected handshake")
        while True:
            line = f.readline().strip()
            if not line:
                break
            key, value = line.split(":", 1)
            self.resp_headers[key.strip()] = value.strip()
        self.handshake_completed = True

    def connect(self):
        """Create a connection with the blame server.
        If self.ssl this will also do the SSL handshake
        """
        sock = socket.create_connection((self.host, self.port))
        self.logger.info("Connected...")
        if self.ssl:
            sock = ssl.wrap_socket(sock)
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, sock.getpeercert(True))
            digest = cert.digest("sha256")
            if self.fingerprint_callback and not self.fingerprint_callback(digest):
                raise Exception("Untrusted endpoint")
            self.logger.info("SSL connection established")
        self.blame_sock = sock

    def on_vuln_notify(self, params):
        """Called when a vuln_notify command is sent from the server
        Command arguments format is:
        connection_id vuln_type server_addr server_port app1 version1, app2 version 2..

        connection_id is an opaque blob identifying the connection (currently a uuid4)
        vuln_type is one of nogotofail.mitm.util.vuln.*
        server_addr and server_port are the remote of the vulnerable connnection.

        In addition there are 0 or more applications sent, each a (name, version) tuple as
        sent by a response to a tcp_client_id request
        """
        id, type, server_addr, server_port = params[:4]
        remaining = " ".join(params[4:])
        applications = remaining.split(", ")
        applications = [Application(*map(urllib.unquote, app.split())) for app in applications]
        if self.vuln_callback:
            self.vuln_callback(id, type, server_addr, server_port, applications)
        return "OK"

    def on_tcp_client_id(self, params):
        """Called when a tcp_client_id command is sent from the server
        Command arguments format is:
        source_port encoded_dest_ip dest_port

        source_port is the source port of the connection
        encoded_ip is the hex encoded output of socket.inet_pton of the destination IP
        dest_port is the destination port in the connection
        """
        source_port = int(params[0])
        dest_ip = None
        dest_port = -1
        if len(params) > 1:
            dest_ip_bytes = params[1].decode("hex")
            if len(dest_ip_bytes) == 4:
                family = socket.AF_INET
            elif len(dest_ip_bytes) == 16:
                family = socket.AF_INET6
            else:
                raise ValueError("Wrong size dest_ip")
            dest_ip = socket.inet_ntop(family, dest_ip_bytes)
        if len(params) > 2:
            dest_port = int(params[2])
        if self.info_callback:
            applications = self.info_callback(source_port, dest_ip, dest_port)
            if applications:
                return ", ".join(("%s %s" % (urllib.quote(app.application), app.version)
                    for app in applications))
        return ""

    command_handlers = {
      "tcp_client_id" : on_tcp_client_id,
      "vuln_notify": on_vuln_notify,
            }


    def run(self):
        """Run the command loop for the blame connection.

        handshake() MUST have been called before this.
        """
        if not self.handshake_completed:
            raise ValueError("Handshake not completed")
        f = self.blame_sock.makefile()
        while True:
            line = f.readline().strip()
            if not line:
                break
            params = line.split(" ")
            tx_id, command = params[:2]
            handler = self.command_handlers.get(command)
            reply_payload = None
            if handler:
                reply_payload = handler(self, params[2:])
            else:
                reply_payload = "ERROR: Unknown command"
            if not reply_payload:
                reply_payload = ""
            f.write("%s %s\r\n" % (tx_id, reply_payload))
            f.flush()
