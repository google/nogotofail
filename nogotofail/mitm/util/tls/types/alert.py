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
import struct
from nogotofail.mitm.util import Constants

level_names = {
    1: "warning",
    2: "fatal",
}

description_names = {
    0:  "close_notify",
    10:  "unexpected_message",
    20:  "bad_record_mac",
    21:  "decryption_failed",
    22:  "record_overflow",
    30:  "decompression_failure",
    40:  "handshake_failure",
    41:  "no_certificate",
    42:  "bad_certificate",
    43:  "unsupported_certificate",
    44:  "certificate_revoked",
    45:  "certificate_expired",
    46:  "certificate_unknown",
    47:  "illegal_parameter",
    48:  "unknown_ca",
    49:  "access_denied",
    50:  "decode_error",
    51:  "decrypt_error",
    60:  "export_restriction",
    70:  "protocol_version",
    71:  "insufficient_security",
    80:  "internal_error",
    86:  "inappropriate_fallback",
    90:  "user_canceled",
    100: "no_renegotiation",
    110: "unsupported_extension",
}

class Alert(object):

    class DESCRIPTION(Constants):
        _constants = Constants.constants(
                {name.upper(): value for value, name in description_names.items()})

    class LEVEL(Constants):
        _constants = Constants.constants(
                {name.upper(): value for value, name in level_names.items()})

    def __init__(self, level, description):
        self.level = level
        self.description = description

    @staticmethod
    def from_stream(body):

        level, description = struct.unpack_from("BB", body, 0)

        return Alert(level, description), 2

    def to_bytes(self):
        return struct.pack("BB", self.level, self.description)

    def __str__(self):
        return ("TLS alert: %s (%d) %s (%d)"
            % (level_names.get(self.level), self.level,
               description_names.get(self.description), self.description))
