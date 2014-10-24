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
from nogotofail.mitm.util.ssl2 import types


def parse_ssl2(message, enforce_length=True):
    """Try and parse an SSLv2 Record from message.

    Message should be the byte representation of an SSLv2 Record.
    Returns a nogotofail.mitm.util.ssl2.Sslv2Record on success or None or error.
    If enforce_length is True then parse_ssl2 will return None if there are
    bytes remaining in message after parsing the record.
    """
    try:
        record, size = types.Sslv2Record.from_stream(message)
        if enforce_length and size != len(message):
            return None
        return record
    except (IndexError, ValueError, struct.error) as e:
        return None
