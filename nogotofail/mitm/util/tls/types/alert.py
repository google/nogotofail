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


class Alert(object):
    LEVEL_FATAL = 2
    LEVEL_WARNING = 1

    def __init__(self, level, description):
        self.level = level
        self.description = description

    @staticmethod
    def from_stream(body):

        level, description = struct.unpack_from("BB", body, 0)

        return Alert(level, description), 2

    def to_bytes(self):
        return struct.pack("BB", self.level, self.description)
