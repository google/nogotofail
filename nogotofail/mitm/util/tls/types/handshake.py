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
from nogotofail.mitm.util.tls.types import parse
from nogotofail.mitm.util.tls.types import Cipher, Extension, Version, Random, CompressionMethod
import base64
import struct


class ServerHelloDone(object):

    def __init__(self):
        pass

    @staticmethod
    def from_stream(body):
        return ServerHelloDone(), 0

    def to_bytes(self):
        return ""


class ServerHello(object):

    def __init__(
        self, version, random, session_id, cipher, compression_method,
        extensions):
        self.version = version
        self.random = random
        self.session_id = session_id
        self.cipher = cipher
        self.compression_method = compression_method
        self.extension_list = extensions
        self.extensions = {ext.name: ext for ext in extensions}

    @staticmethod
    def from_stream(body):
        """Parse a Server Hello record from body.

        Body should start with the byte representation of an RFC 5246
        struct Server Hello.
        Returns a ServerHello and the number of bytes read from body

        Throws a struct.error or IndexError if there is not enough data to parse
        properly.
        """
        version, index = Version.from_stream(body)

        random, read_amt = Random.from_stream(body[index:])
        index += read_amt

        sessionid_length = struct.unpack_from("B", body, index)[0]
        index += 1
        session_id, read_amt = (
            parse.parse_tls_list(
                body[index:], sessionid_length,
                parse.parse_opaque))
        index += read_amt

        cipher, read_amt = Cipher.from_stream(body[index:])
        index += read_amt

        method, read_amt = CompressionMethod.from_stream(body[index:])
        index += read_amt

        extensions = []
        # Check if there are extensions present
        if len(body) != index:
            extensions_length = struct.unpack_from("!H", body, index)[0]
            index += 2
            extensions, read_amt = (
                parse.parse_tls_list(
                    body[index:], extensions_length,
                    Extension.from_stream))
            index += read_amt
        return ServerHello(
            version, random, session_id, cipher, method, extensions), index

    def to_bytes(self):
        return (
            self.version.to_bytes() + self.random.to_bytes() + parse.to_tls_list(
                self.session_id,
                parse.to_opaque,
                "B") +
            self.cipher.to_bytes() + self.compression_method.to_bytes() +
            (
                ""
                if len(self.extension_list) == 0 else parse.to_tls_list(
                    self.extension_list, Extension.to_bytes, "!H")))

    def __str__(self):
        extensions = "\n".join(
            map(lambda s: "\t" + str(s), self.extension_list))
        session_id = ""
        return "Server Hello\n%s\n%s\n"\
        "Session id:%s\n"\
        "Cipher: %s\n"\
        "Compression Method: %s\n"\
        "Extensions:\n%s\n" % (self.version, self.random, self.session_id, self.cipher, self.compression_method, extensions)


class ClientHello(object):

    def __init__(
        self, version, random, session_id, ciphers, compression_methods,
        extensions):
        self.version = version
        self.random = random
        self.session_id = session_id
        self.ciphers = ciphers
        self.compression_methods = compression_methods
        self.extension_list = extensions
        self.extensions = {ext.name: ext for ext in extensions}

    def __str__(self):
        extensions = "\n".join(
            map(lambda s: "\t" + str(s), self.extension_list))
        ciphers = "\n".join(map(lambda s: "\t" + str(s), self.ciphers))
        methods = "\n".join(
            map(lambda s: "\t" + str(s), self.compression_methods))
        session_id = ""
        return "Client Hello\n%s\n%s\n"\
        "Session id:%s\n"\
        "Ciphers:\n"\
        "%s\n"\
        "Compression Methods:\n"\
        "%s\n"\
        "Extensions:\n%s\n" % (self.version, self.random, self.session_id, ciphers, methods, extensions)

    @staticmethod
    def from_stream(body):
        """Parse a Client Hello record from body.

        Body should start with the byte representation of an RFC 5246
        struct ClientHello
        Returns a ClientHello and the number of bytes read from body

        Throws a struct.error or IndexError if there is not enough data to parse
        properly.
        """
        version, index = Version.from_stream(body)

        random, read_amt = Random.from_stream(body[index:])
        index += read_amt

        sessionid_length = struct.unpack_from("B", body, index)[0]
        index += 1
        session_id, read_amt = (
            parse.parse_tls_list(
                body[index:], sessionid_length,
                parse.parse_opaque))
        index += read_amt

        cipher_length = struct.unpack_from("!H", body, index)[0]
        index += 2
        ciphers, read_amt = (
            parse.parse_tls_list(
                body[index:], cipher_length,
                Cipher.from_stream))
        index += read_amt

        compression_length = struct.unpack_from("B", body, index)[0]
        index += 1
        compression_methods, read_amt = (
            parse.parse_tls_list(
                body[index:], compression_length,
                CompressionMethod.from_stream))
        index += read_amt

        extensions = []
        # Check if there are extensions present
        if index != len(body):
            extensions_length = struct.unpack_from("!H", body, index)[0]
            index += 2
            extensions, read_amt = (
                parse.parse_tls_list(
                    body[index:], extensions_length,
                    Extension.from_stream))
            index += read_amt

        return ClientHello(
            version, random, session_id, ciphers, compression_methods,
            extensions), index

    def to_bytes(self):
        return (self.version.to_bytes() +
            self.random.to_bytes() +
            parse.to_tls_list(self.session_id, parse.to_opaque, "B") +
            parse.to_tls_list(self.ciphers, Cipher.to_bytes, "!H") +
            parse.to_tls_list(
                self.compression_methods,
                CompressionMethod.to_bytes,
                "B") +
            (
                ""
                if len(self.extension_list) == 0 else parse.to_tls_list(
                    self.extension_list, Extension.to_bytes, "!H")))


class OpaqueMessage(object):

    def __init__(self, body):
        self.body = body

    @staticmethod
    def from_stream(body):
        return OpaqueMessage(body), len(body)

    def to_bytes(self):
        return self.body

typemap = {
    1: ClientHello,
    2: ServerHello,
    14: ServerHelloDone,
}


class HandshakeMessage(object):

    def __init__(self, type, obj):
        self.obj = obj
        self.type = type

    @staticmethod
    def from_stream(body):
        # Parse The Handshake. Length is 24bits which struct doesn't support
        # well.
        msg_type, length = struct.unpack("!BI", body[0] + "\x00" + body[1:4])
        body = body[4:4 + length]
        if length != len(body):
            raise ValueError("Not enough data in body")
        # Check this is a supported type
        type = typemap.get(msg_type, OpaqueMessage)
        obj, size = type.from_stream(body)
        if len(body) != size:
            raise ValueError("Read mismatch")
        return HandshakeMessage(msg_type, obj), length + 4

    def to_bytes(self):
        obj_bytes = self.obj.to_bytes()
        return struct.pack("B", self.type) + struct.pack(
            "!I", len(obj_bytes))[1:] + obj_bytes
