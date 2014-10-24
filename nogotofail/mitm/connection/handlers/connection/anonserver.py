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
from nogotofail.mitm.connection.handlers.connection import LoggingHandler
from nogotofail.mitm.connection.handlers.connection import handlers
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection


@handler(handlers, default=True)
class AnonServerMITM(LoggingHandler):

    name = "anonserver"
    description = (
        "Attempts to MiTM connections that accept anonymous/unauthenticated "
        "server.")
    success = False
    vuln = util.vuln.VULN_TLS_ANON_SERVER

    def on_request(self, request):
        if not self.success and self.ssl:
            self.log(logging.CRITICAL, "MITM Success without server cert!")
            self.log_event(
                logging.CRITICAL,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    None))
            self.success = True
            self.connection.vuln_notify(self.vuln)
        return super(AnonServerMITM, self).on_request(request)

    def on_response(self, response):
        if not self.success and self.ssl:
            self.log(logging.CRITICAL, "MITM Success without server cert!")
            self.log_event(
                logging.CRITICAL,
                connection.AttackEvent(
                    self.connection, self.name, True,
                    None))
            self.success = True
            self.connection.vuln_notify(self.vuln)
        return super(AnonServerMITM, self).on_response(response)

    def on_ssl(self, client_hello):
        super(AnonServerMITM, self).on_ssl(client_hello)
        return True

    def on_server_cipher_suites(self, client_hello):
        super(AnonServerMITM, self).on_server_cipher_suites(client_hello)
        return "aNULL"

    def on_close(self, handler_initiated):
        super(AnonServerMITM, self).on_close(handler_initiated)
        if not self.success:
            self.log_event(
                logging.INFO,
                connection.AttackEvent(
                    self.connection, self.name, False,
                    None))

