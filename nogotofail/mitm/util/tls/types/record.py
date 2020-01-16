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
from nogotofail.mitm.util import Constants
from nogotofail.mitm.util.tls.types import parse
from nogotofail.mitm.util.tls.types import HandshakeMessage, Version, ChangeCipherSpec, Alert
from nogotofail.mitm.util.tls.types import TlsRecordIncompleteError, TlsMessageFragmentedError, TlsNotEnoughDataError
import base64
import struct

name_map = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}


class TlsRecord(object):

    class CONTENT_TYPE(Constants):
        _constants = {name.upper(): value for value, name in name_map.items()}


    type_map = {
        CONTENT_TYPE.CHANGE_CIPHER_SPEC: ChangeCipherSpec,
        CONTENT_TYPE.ALERT: Alert,
        CONTENT_TYPE.HANDSHAKE: HandshakeMessage,
    }

    def __init__(self, content_type, version, messages):
        self.content_type = content_type
        self.version = version
        self.messages = messages

    @staticmethod
    def from_stream(body, previous_fragment_data=""):
        # Parse the TLS Record
        content_type, version_major, version_minor, length = (
            struct.unpack_from("!BBBH", body, 0))
        # Sanity checks
        if version_major != 3 or version_minor > 3:
            raise ValueError("Bad TLS Version for SSL3-TLS1.2 parsing")
        if content_type not in name_map:
            raise ValueError("Unknown content type %d" % content_type)

        fragment = body[5:5 + length]
        original_fragment = fragment
        # Merge in any old fragmented data
        fragment = previous_fragment_data + fragment
        if len(fragment) < length:
            raise TlsRecordIncompleteError(len(fragment), length)
        # Start parsing the objects from the record
        type = TlsRecord.type_map.get(content_type, OpaqueFragment)
        objs = []
        try:
            if fragment == "":
                obj, size = type.from_stream(fragment)
                objs.append(obj)

            while fragment != "":
                obj, size = type.from_stream(fragment)
                objs.append(obj)
                fragment = fragment[size:]
        except TlsNotEnoughDataError:
            # In the event of not enough data throw what we have up to a higher
            # level
            raise TlsMessageFragmentedError(original_fragment, 5 + length)
        return TlsRecord(content_type, Version(version_major, version_minor),
                         objs), 5 + length

    def to_bytes(self, max_fragment_size = 2 ** 12):
        bytes = "".join([message.to_bytes() for message in self.messages])
        # Fragment the record as needed
        num_fragments = len(bytes)/max_fragment_size
        fragments = [bytes[i: i + max_fragment_size] for i in range (0, len(bytes), max_fragment_size)]
        return "".join([(struct.pack("B", self.content_type)
                    + self.version.to_bytes()
                    + struct.pack("!H", len(fragment))
                    + fragment) for fragment in fragments])

    def __str__(self):
        return ("TLS Record %s %s (%d)"
            % (self.version, name_map.get(self.content_type), self.content_type))


class OpaqueFragment(object):

    def __init__(self, fragment):
        self.fragment = fragment

    @staticmethod
    def from_stream(body):
        return OpaqueFragment(body), len(body)

    def to_bytes(self):
        return self.fragment
