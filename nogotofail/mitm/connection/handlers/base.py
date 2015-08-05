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

class BaseHandler(object):

    # The string used to reference this handler. This will be shown in logs and --help
    name = "handler"
    # Human readable description of what this handler does.
    # Should describe things like attacks
    description = "Basic connection handler. Does nothing but bridge traffic."
    # If the handler is passive and should do no modification
    passive = False

    def __init__(self, connection):
        self.connection = connection

    def on_request(self, request):
        """Called when the client sends a request to the server.

        request contains the data sent from the client.
        Returns the data to send to the server.
        """
        return request

    @staticmethod
    def check_precondition():
        """Check if the handler is able to be used in the current run of nogotofail.
        This should ensure that any required files exist and similar preconditions
        to the handler being used.

        Returns tuple (precondition_success, error_message)
        precondition_success: if all preconditions are met
        error_message: message to be logged explaining the failure if precondition_success is False.
        """
        return True, ""

    def on_inject_request(self, request):
        """Called when a handler is injecting a request to the server.
        NOTE: Modifying injected data can put other handlers in weird states and should be avoided.

        request contains the data to be sent to the server.
        Returns the data to send to the server.
        """
        return request

    def on_response(self, response):
        """Called when the server sends a response to the client.

        response contains the data sent from the server.
        Returns the data to send to the client.
        """
        return response

    def on_inject_response(self, response):
        """Called when a handler is injecting a response to the client.
        NOTE: Modifying injected data can put other handlers in weird states and should be avoided.

        response contains the data to be sent to the client.
        Returns the data to send to the client.
        """
        return response

    def on_remove(self):
        """Called when this handler is removed
        """
        pass

    def on_select(self):
        """Called when the handler is selected for use with a connection but before the connection is set up.
        """
        pass

    def on_establish(self):
        """Called when the connection is established with both parties.
        """
        pass

    def on_close(self, handler_initiated):
        """Called when the connection has been closed.

        if handler_initiated is true then a handler closed the connection, otherwise one of
        the endpoints caused the close.
        """
        pass

    def on_ssl(self, client_hello):
        """Called when a TLS ClientHello is detected in the stream.
        """
        pass


class BaseConnectionHandler(BaseHandler):

    def on_certificate(self, server_cert):
        """Called when the Connection needs a certificate for the remotely provided server_cert.

        Returns a path to a file containing a PEM encoded certificate
        chain and private key.
        """
        return None

    def on_server_cipher_suites(self, client_hello):
        """Called when the Connection needs a list of cipher suites to be enabled for the server.

        Returns a list of cipher suites in OpenSSL Cipher List Format or None for the default list.
        See https://www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT.
        """
        return None

    def on_ssl(self, client_hello):
        """Called when a TLS ClientHello is detected in the stream.

        Returns if the connection should be man in the middled.
        """
        return False

    def on_ssl_establish(self):
        """Called when the ssl man in the middle connection has been established with both parties.

        Note: This does not mean a man in the middle was successful. Many
        applications will
        complete the connection but not actually use it or close it immediately.
        """
        self.ssl = True

    def on_ssl_error(self, error):
        """Called when an OpenSSL.SSL.Error is caught.
        """
        pass
