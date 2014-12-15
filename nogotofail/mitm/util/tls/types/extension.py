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
import string
import struct
import base64
from nogotofail.mitm.util import Constants
from nogotofail.mitm.util.tls.types import parse

# Map of extension_types to strings
name_map = {
    0: "server_name",
    1: "max_fragment_length",
    2: "client_certificate_url",
    3: "trusted_ca_keys",
    4: "truncated_hmac",
    5: "status_request",
    6: "user_mapping",
    7: "client_authz",
    8: "server_authz",
    9: "cert_type",
    10: "elliptic_curves",
    11: "ec_point_formats",
    12: "srp",
    13: "signature_algorithms",
    14: "use_srtp",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    17: "status_request_v2",
    18: "signed_certificate_timestamp",
    19: "client_certificate_type",
    20: "server_certificate_type",
    21: "padding",
    35: "SessionTicket",
    13172: "next_protocol_negotiation",
    30031: "Channel ID (old)",
    30032: "Channel ID (new)",
    65281: "renegotiation_info",
}


class Extension(object):

    class TYPE(Constants):
        _constants = Constants.constants(
                {name.translate(string.maketrans(" ","_"),"()").upper() : value
                    for value, name in name_map.items()})

    def __init__(self, extension_type, extension_data):
        self.type = extension_type
        self.raw_data = extension_data
        self.data = Extension.parse_data(self.type, self.raw_data)

    @property
    def name(self):
        return name_map.get(self.type)

    def __str__(self):
        return "%s" % (self.name if self.name else self.type)

    @staticmethod
    def from_stream(body):
        extension_type = struct.unpack_from("!H", body, 0)[0]
        data_length = struct.unpack_from("!H", body, 2)[0]
        extension_data, read_amt = parse.parse_tls_list(
            body[4:], data_length, parse.parse_opaque)
        return Extension(extension_type, list(extension_data)), 4 + read_amt

    def to_bytes(self):
        return struct.pack("!H", self.type) + parse.to_tls_list(
            self.raw_data, parse.to_opaque, "!H")

    @staticmethod
    def parse_data(type, data):
        data = "".join(data)
        # currently only parsing SNI
        if type != 0:
            return data
        if len(data) == 0:
            return ""
        # parse out the SNI list
        size = struct.unpack_from("!H", data, 0)[0]
        snis = parse.parse_tls_list(data[2:], size, _parse_sni)[0]
        for sni in snis:
            if sni[0] == 0:
                return sni[1]
        # Didn't parse out a server name?
        return ""


def _parse_sni(data):
    type = struct.unpack_from("B", data, 0)[0]
    size = struct.unpack_from("!H", data, 1)[0]
    name = parse.parse_tls_list(data[3:], size, parse.parse_opaque)[0]
    return (type, "".join(name)), size + 3
