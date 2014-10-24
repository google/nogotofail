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
class HandlerStore(object):
    map = None
    all = None
    default = None
    internal = None

    def __init__(self):
        self.map = {}
        self.all = []
        self.default = []
        self.internal = []


def handler(store, default=False, internal=False):
    def wrapper(cls):
        if internal:
            store.internal.append(cls)
        else:
            store.map[cls.name] = cls
            store.all.append(cls)
            if default:
                store.default.append(cls)
        return cls
    return wrapper
