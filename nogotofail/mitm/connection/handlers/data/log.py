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
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
from nogotofail.mitm.event import connection


@handler.passive(handlers, default=True)
class RawTrafficLogger(DataHandler):
    name = "rawlogger"
    description = "Log raw traffic to the traffic log"
    traffic_logger = logging.getLogger("traffic")

    def log_traffic(self, level, event):
        self.traffic_logger.log(level, event.dumps())

    def on_establish(self):
        self.log_traffic(
            logging.INFO,
            connection.ConnectionEstablished(self.connection))

    def on_request(self, request):
        if self.traffic_logger.isEnabledFor(logging.INFO):
            self.log_traffic(
                logging.INFO,
                connection.TrafficEvent(self.connection, request, "client"))
        return request

    def on_response(self, response):
        if self.traffic_logger.isEnabledFor(logging.INFO):
            self.log_traffic(
                logging.INFO,
                connection.TrafficEvent(self.connection, response, "server"))
        return response

    def on_inject_request(self, request):
        if self.traffic_logger.isEnabledFor(logging.INFO):
            self.log_traffic(
                logging.INFO,
                connection.TrafficEvent(self.connection, request, "client", injected=True))
        return request

    def on_inject_response(self, response):
        if self.traffic_logger.isEnabledFor(logging.INFO):
            self.log_traffic(
                logging.INFO,
                connection.TrafficEvent(self.connection, response, "server", injected=True))
        return response

    def on_close(self, handler_initiated):
        self.log_traffic(
            logging.INFO, connection.ConnectionClosed(self.connection, handler_initiated))
