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
import base64
from collections import namedtuple
import logging
from nogotofail.mitm import util
from nogotofail.mitm.connection.handlers.data import handlers
from nogotofail.mitm.connection.handlers.data import DataHandler
from nogotofail.mitm.connection.handlers.store import handler
import re
import time
import uuid


class CallbackMap(object):
    Entry = namedtuple("Entry", ["id", "func", "timeout", "start"])
    SWEEP_RATE = 10

    def __init__(self):
        self.map = {}
        self.last_sweep = time.time()

    def add(self, func, id=None, timeout=2):
        if id is None:
            id = str(uuid.uuid4())
        if id in self.map:
            raise KeyError("id already in use")
        self.map[id] = CallbackMap.Entry(id, func, timeout, time.time())
        self.sweep(force=False)
        return id

    def sweep(self, force=True):
        now = time.time()
        if not force and now - self.last_sweep < self.SWEEP_RATE:
            return
        self.last_sweep = now
        for id, entry in self.map.items():
            if now - entry.start > entry.timeout:
                entry.func(None)
                del self.map[id]

    def call(self, id, data):
        if not id in self.map:
            raise KeyError()
        entry = self.map[id]
        cont = entry.func(data)
        if not cont:
            del self.map[id]


callbacks = CallbackMap()


@handler(handlers, internal=True)
class ClientReportDetection(DataHandler):
    name = "clientreport"
    description = (
        "detects vulnerability reports from the client and routes them to "
        "handlers")
    token = base64.standard_b64encode(str(uuid.uuid4()))

    def on_request(self, request):
        callbacks.sweep(force=False)
        http = util.http.parse_request(request)
        if not (http and not http.error_code):
            return request
        url = http.path
        match = re.match(".*%s:(.*)$" % (self.token), url)
        if not match:
            return request

        try:
            id, data = match.group(1).split(",", 1)
            id = base64.standard_b64decode(id)
        except ValueError:
            self.log(
                logging.DEBUG,
                "Malformed data from client: %s" % (match.group(1)))
            return request
        try:
            callbacks.call(id, data)
        except KeyError:
            self.log(logging.DEBUG, "Got request for expired handler, id=" % id)

        # Strip out the data and send it along
        return request.replace("?%s:%s" % (self.token, match.group(1)), "", 1)

    @staticmethod
    def add_callback_url(callback, base_url, data="", timeout=2):
        """Build a url that, when requested by the client, will cause a callback to be triggered

        Arguments:
            callback: The function to be called. It should take 1 argument(the
              data or None on
                      timeout) and returns if the callback shoudl remain mapped.
            base_url: The base url to use to build the detection URL on top of.
            data: The data to include to the callback. if empty the data can be
              appended to the
                  returned url at a latter time
            timeout: How long the callback should remain live for.

        Returns the url to trigger detection. If data is empty it is safe to
          append the data
        to the url directly.
        """
        id = callbacks.add(callback, timeout=timeout)
        id = base64.standard_b64encode(str(id))
        url = base_url + "?%s:%s,%s" % (ClientReportDetection.token, id, data)
        return url
