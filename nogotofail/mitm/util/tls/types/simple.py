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
import base64


class Random(object):

    def __init__(self, gmt_unix_time, random_bytes):
        self.gmt_unix_time = gmt_unix_time
        self.bytes = random_bytes

    def __str__(self):
        return "Random(%d, %s)" % (
            self.gmt_unix_time, base64.b64encode(self.bytes))

    @staticmethod
    def from_stream(body):
        if len(body) < 32:
            raise ValueError("Not enough data to unpack")
        gmt_unix_time = struct.unpack_from("!I", body, 0)[0]
        random_bytes = body[4:32]
        return Random(gmt_unix_time, random_bytes), 32

    def to_bytes(self):
        return struct.pack("!I", self.gmt_unix_time) + self.bytes


class Version(object):

    def __init__(self, major, minor):
        self.major = major
        self.minor = minor

    def __str__(self):
        return "Version %d.%d" % (self.major, self.minor)

    @staticmethod
    def from_stream(body):
        major, minor = struct.unpack_from("BB", body, 0)
        return Version(major, minor), 2

    def to_bytes(self):
        return struct.pack("BB", self.major, self.minor)

