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
from nogotofail.mitm.util.tls.types import parse, Version, Random, CompressionMethod
from nogotofail.mitm.util.ssl2.types import Cipher
import struct

class ClientHello(object):

    def __init__(
        self, version, random, session_id, ciphers):
        self.version = version
        self.random = random
        self.session_id = session_id
        self.ciphers = ciphers
        self.compression_method = [CompressionMethod(0)]
        self.extension_list = []
        self.extensions = {}

    def __str__(self):
        ciphers = "\n".join(map(lambda s: "\t" + str(s), self.ciphers))
        session_id = ""
        return "SSLv2 Client Hello\n%s\n%s\n"\
        "Session id:%s\n"\
        "Ciphers:\n"\
        "%s\n" % (self.version, self.random, self.session_id, ciphers)

    @staticmethod
    def from_stream(body):
        """Parse a SSLv2 Client Hello record from body.

        Body should start with the byte representation struct ClientHello
        starting at the version field.
        See http://tools.ietf.org/html/rfc5246#appendix-E.2
        Returns a ClientHello and the number of bytes read from body

        Throws a struct.error or IndexError if there is not enough data to parse
        properly.
        """
        version, index = Version.from_stream(body)
        ciphers_length, sessionid_length, random_length = struct.unpack_from(
            "!HHH", body, index)
        index += 6;
        if ciphers_length % 3 != 0:
            raise ValueError("Cipher spec list length not a multiple of 3")
        if ciphers_length + sessionid_length + random_length \
           != len(body) - index:
            raise ValueError("Not enough data or too much data")
        if random_length < 16 or random_length > 32:
            raise ValueError("Random challenge too short or too long")

        ciphers, read_amt = (
            parse.parse_tls_list(
                body[index:], ciphers_length,
                Cipher.from_stream))
        index += read_amt

        session_id, read_amt = (
            parse.parse_tls_list(
                body[index:], sessionid_length,
                parse.parse_opaque))
        index += read_amt

        random = body[index:index + random_length]
        index += random_length

        return ClientHello(
            version, random, session_id, ciphers), index

typemap = {
    1: ClientHello,
}

class HandshakeMessage(object):

    def __init__(self, type, obj):
        self.obj = obj
        self.type = type

    @staticmethod
    def from_stream(body):
        if len(body) < 3:
            raise ValueError("Not enough data")
        # TODO: Support for long (3 byte) header
        if ord(body[0]) & 0x80 == 0:
            raise ValueError("Long header not supported")
        length, msg_type = struct.unpack_from("!HB", body, 0)
        length &= 0x7fff
        msg_data = body[3:2 + length]
        if len(msg_data) != length - 1:
            raise ValueError("Not enough data")
        type = typemap.get(msg_type)
        if not type:
            raise ValueError("Unsupported message type: %d" % msg_type)
        obj, size = type.from_stream(msg_data)
        if len(msg_data) != size:
            raise ValueError("Read mismatch")
        return HandshakeMessage(msg_type, obj), 2 + length

