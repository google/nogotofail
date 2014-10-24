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
import re
import shlex


@handler(handlers, default=True)
class CustomRequestDetection(DataHandler):
    """Looks for messages specified by the client(in the blame handshake) in requests.

    Supports a list of regex's in the client's Request-Detection header in shell
    form.

    Example header:
    Request-Detection: "([0-9][0-9][0-9]-?)?867-?5309" "super secret data"
    """
    name = "customrequest"
    description = "Detect client specified regexs in requests"
    regexs = None

    def on_select(self):
        client = self.connection.app_blame.clients.get(
            self.connection.client_addr)
        client = client.info if client else None
        if not (client and "Request-Detection" in client["headers"]):
            self.regexs = []
            return
        regexs = []
        for regex_str in shlex.split(client["headers"]["Request-Detection"]):
            try:
                regex = re.compile(regex_str)
                regexs.append(regex)
            except re.error as e:
                self.log(logging.INFO,
                         "Failed to parse user regex \"%s\", %s." %
                         (regex_str, e))
        self.regexs = regexs

    def on_request(self, request):
        for regex in self.regexs:
            if regex.search(request):
                self.log(
                    logging.CRITICAL,
                    "Request matched pattern \"%s\"." % regex.pattern)
                self.connection.vuln_notify(util.vuln.VULN_CUSTOM_REQUEST_MATCH)

        return request
