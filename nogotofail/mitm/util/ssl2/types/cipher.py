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
from nogotofail.mitm.util.tls.types import Cipher as SSLv3Cipher
import array
import struct


class Cipher(object):

    def __init__(self, bytes):
        self.bytes = bytes

    @property
    def name(self):
        result = name_map.get(self.bytes)
        if not result is None:
            return result
        if self.bytes[0] == 0:
            # SSLv3 or newer cipher suite
            return SSLv3Cipher.from_stream(struct.pack("BB", *self.bytes[1:3]))[0].name
        return None

    @staticmethod
    def from_stream(body):
        cipher = struct.unpack_from("BBB", body, 0)
        return Cipher(cipher), 3

    def __str__(self):
        name = self.name
        if name:
            return name
        else:
            return "(0x%x,0x%x,0x%x)" % self.bytes

    def to_bytes(self):
        return struct.pack("BBB", *self.bytes)

name_map = {
  (0x01, 0x00, 0x80): "SSL2_RC4_128_WITH_MD5",
  (0x02, 0x00, 0x80): "SSL2_RC4_128_EXPORT40_WITH_MD5",
  (0x03, 0x00, 0x80): "SSL2_CK_RC2_128_CBC_WITH_MD5",
  (0x04, 0x00, 0x80): "SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
  (0x05, 0x00, 0x80): "SSL2_CK_IDEA_128_CBC_WITH_MD5",
  (0x06, 0x00, 0x40): "SSL2_CK_DES_64_CBC_WITH_MD5",
  (0x07, 0x00, 0xC0): "SSL2_DES_192_EDE3_CBC_WITH_MD5",
}
