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
from nogotofail.mitm.event.base import Event


class ConnectionEvent(Event):
    """Event for things related to connections.

    Data sent, Attack success, application info, etc
    """
    # identifier for this connection. Should be unique.
    connection_id = None
    # Connection pairs
    client_addr = None
    client_port = None
    server_addr = None
    server_port = None

    blame_info = None
    handler = None

    def __init__(self, connection, time=None):
        super(ConnectionEvent, self).__init__(time)

        self.connection_id = str(connection.id)
        self.client_addr = connection.client_addr
        self.client_port = connection.client_port
        self.server_addr = connection.server_addr
        self.server_port = connection.server_port
        if connection.hostname:
            self.hostname = connection.hostname
        # Use the cached value only, don't force a lookup
        blame_info = connection.applications(cached_only=True)
        if blame_info:
            self.platform_info = blame_info[0]
            self.applications = [(app.package, app.version)
                                 for app in blame_info[1]]
        client = connection.client_info
        if client:
            if "Installation-ID" in client.info:
                self.installation_id = client.info["Installation-ID"]
        self.handler = connection.handler.name


class TrafficEvent(ConnectionEvent):

    def __init__(self, connection, data, source, injected=False, time=None):
        super(TrafficEvent, self).__init__(connection, time)
        self.data = data.encode("base64")
        self.source = source
        self.injected = injected


class AttackEvent(ConnectionEvent):

    def __init__(self, connection, handler, success, data, time=None):
        super(AttackEvent, self).__init__(connection, time)
        self.handler = handler
        self.data = data
        self.success = success


class ConnectionEstablished(ConnectionEvent):
    pass


class ConnectionClosed(ConnectionEvent):
    def __init__(self, connection, handler_initiated, time=None):
        super(ConnectionClosed, self).__init__(connection, time)
        self.handler_initiated = handler_initiated


class HandlerRemoved(ConnectionEvent):

    def __init__(self, connection, time=None):
        super(HandlerRemoved, self).__init__(connection, time)


class ClientHello(ConnectionEvent):

    def __init__(self, connection, client_hello, time=None):
        super(ClientHello, self).__init__(connection, time)
        self.client_hello = client_hello


class SSLEstablished(ConnectionEvent):
    pass
