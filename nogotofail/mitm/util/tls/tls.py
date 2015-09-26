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
from nogotofail.mitm.util.tls import types

def parse_tls(message, throw_on_incomplete=False):
    """Try and parse a TLS record. If the message is fragmented over multiple TLS records this
    will return one TLS record with the defragmented payload

    Arguments:
    message -- wire representation of a TLS message.
    throw_on_incomplete -- throw a TlsRecordIncompleteError or TlsMessageFragmentedError if
        message is not complete, otherwise return None

    Returns (nogotofail.mitm.util.tls.TlsRecord, remaining_message) if message consumed
        or None, message if parsing was unsuccessful
    """
    extra_fragment_data = ""
    original_message = message
    try:
        while message:
            try:
                record, size = types.TlsRecord.from_stream(message,
                        previous_fragment_data=extra_fragment_data)
                return record, message[size:]
            except types.TlsMessageFragmentedError as e:
                # If we're fragmented try and keep parsing
                extra_fragment_data += e.fragment_data
                message = message[e.data_consumed:]
                # If we're fragmented but out of data error out
                if not message:
                    if throw_on_incomplete:
                        raise e
                    else:
                        return None, original_message
    except (IndexError, ValueError, struct.error):
        return None, original_message
    except types.TlsRecordIncompleteError as e:
        if throw_on_incomplete:
            raise e
        else:
            return None, original_message
    return None, original_message
