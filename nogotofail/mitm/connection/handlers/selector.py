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
from nogotofail.mitm.connection import handlers


def default_connection_selector(connection, app_blame):
    """Returns a nogotofail.mitm.connection.handlers ConnectionHandler to be used to handle the connection.
    """
    return handlers.BaseConnectionHandler


def default_ssl_connection_selector(connection, app_blame, client_hello):
    """Returns a nogotofail.mitm.connection.handlers class to use for establishing a SSL connection on connection. If None is returned the connection will continue to use the current handler.
    """
    return None


def default_data_selector(connection):
    """Returns a list of nogotofail.mitm.connection.handlers class to use for handling data on connection. Handlers will be invoked in the order they appear in the list. Any modifications to data will be chained down the list.
    """
    return []
