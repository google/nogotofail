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

class Constants(object):
    class _Meta(type):
        def __getattr__(cls, attr):
            if attr in cls.__dict__:
                return cls.__dict__[attr]
            if attr in cls._constants:
                return cls._constants[attr]
            else:
                raise AttributeError(attr)

        def __setattr__(cls, attr, value):
            raise AttributeError("Cannot set constants")

        def __dir__(cls):
            return cls._constants.keys()

    __metaclass__ = _Meta

    class Constant():
        def __init__(self, name, value):
            self.name = name
            self.value = value
        def __getattr__(self, attr):
            return getattr(self.value, attr)
        def __str__(self):
            return self.name
        def __repr__(self):
            return self.__str__()

    @staticmethod
    def constants(items):
        return {k: Constants.Constant(k, v) for k,v in items.items()}

