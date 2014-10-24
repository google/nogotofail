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
from nogotofail.mitm.util.tls.types import HandshakeMessage, Version, ChangeCipherSpec, Alert
import base64
import struct

type_map = {
    20: ChangeCipherSpec,
    21: Alert,
    22: HandshakeMessage,
}


class TlsRecord(object):

    def __init__(self, content_type, version, messages):
        self.content_type = content_type
        self.version = version
        self.messages = messages

    @staticmethod
    def from_stream(body):
        # Parse the TLS Record
        content_type, version_major, version_minor, length = (
            struct.unpack_from("!BBBH", body, 0))
        fragment = body[5:5 + length]
        # Sanity check
        if length != len(fragment):
            raise ValueError("Not enough data in fragment")
        # Check this is a Handshake message
        type = type_map.get(content_type, OpaqueFragment)
        objs = []
        if fragment == "":
            obj, size = type.from_stream(fragment)
            objs.append(obj)

        while fragment != "":
            obj, size = type.from_stream(fragment)
            objs.append(obj)
            fragment = fragment[size:]
        return TlsRecord(content_type, Version(version_major, version_minor),
                         objs), 5 + length

    def to_bytes(self):
        bytes = "".join([message.to_bytes() for message in self.messages])
        return (struct.pack("B", self.content_type)
                + self.version.to_bytes()
                + struct.pack("!H", len(bytes))
                + bytes)


class OpaqueFragment(object):

    def __init__(self, fragment):
        self.fragment = fragment

    @staticmethod
    def from_stream(body):
        return OpaqueFragment(body), len(body)

    def to_bytes(self):
        return self.fragment
