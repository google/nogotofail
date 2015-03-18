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
import textwrap

from nogotofail.mitm.connection.handlers import base
from nogotofail.mitm.event import connection


class LoggingHandler(base.BaseConnectionHandler):

    name = "logging"
    description = "Logs connection events while bridging. "

    FORMAT = (
        "[%(client_addr)s:%(client_port)s<=>%(server_addr)s:%(server_port)s "
        "%(connection_id)s %(class)s](%(app_str)s) %(message)s")
    logger = logging.getLogger("nogotofail.mitm")
    event_logger = logging.getLogger("event")
    ssl = False

    def log(self, level, message):
        d = {"client_addr": self.connection.client_addr,
             "client_port": self.connection.client_port,
             "server_addr": self.connection.server_addr,
             "server_port": self.connection.server_port,
             "message": message,
             "app_str": self.applications_str,
             "class": self.name,
             "connection_id": self.connection.id}
        self.logger.log(level, self.FORMAT % d)

    def log_event(self, level, event):
        self.event_logger.log(level, event.dumps())

    def log_attack_event(self, data=None, success=True):
        self.log_event(
            logging.ERROR,
            connection.AttackEvent(
                self.connection, self.name, success,
                data))


    @property
    def applications_str(self):
        apps = self.connection.applications()
        if apps is None:
            return "Unknown"
        info, apps = apps
        return "client=%s " % info + ", ".join([
            "application=\"%s\" version=\"%s\"" %
            (app.package, app.version)
            for app in apps])

    def on_select(self):
        self.log(logging.INFO, "Selected for connection")

    def on_establish(self):
        self.log(logging.INFO, "Connection established")

    def on_ssl_error(self, error):
        self.log(logging.DEBUG, "SSL exception: %s " % error)

    def on_close(self, handler_initiated):
        if handler_initiated:
            self.log(logging.INFO, "Connection closed by handler")
        else:
            self.log(logging.INFO, "Connection closed")

    def on_remove(self):
        self.log(logging.INFO, "Handler being removed")

    def on_ssl(self, client_hello):
        self.log(logging.DEBUG, "SSL starting")

    def on_ssl_establish(self):
        self.log(logging.INFO, "SSL connection established")
        self.ssl = True
