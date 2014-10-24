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


def parse_tls_list(buf, size, parse_item_method):
    items = []
    read = 0
    while size > 0:
        item, item_size = parse_item_method(buf)
        items.append(item)
        buf = buf[item_size:]
        size -= item_size
        read += item_size
    if size != 0:
        raise ValueError("Consumed too much data")
    return items, read


def parse_opaque(buf):
    return buf[0], 1


def to_tls_list(items, method, size):
    bytes = "".join(map(lambda item: method(item), items))
    return struct.pack(size, len(bytes)) + bytes


def to_opaque(item):
    return item
