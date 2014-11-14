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

def handler(store, default=True, internal=False, passive=False):
    """ Decorator for setting up a handler.

    This puts the handler into the handler store which can then be used
    to look up all handlers and information about them such as which are default,
    passive, etc.

    Currently there are two handler stores, one for connection handlers in
    nogotofail.mitm.connection.handlers.connection.store and one for data handlers
    in nogotofail.mitm.connection.handlers.data.store

    Arguments:
    store -- the HandlerStore to store information about the handler in
    default -- if the handler should be used by default
    internal -- if the handler is used internally. These are always added and not displayed
        in --help or sent to the client.
    passive -- if the handler is passive and does no modification.
    """
    def wrapper(cls):
        cls.passive = passive

        if internal:
            store.internal.append(cls)
        else:
            store.map[cls.name] = cls
            store.all.append(cls)
            if default:
                store.default.append(cls)
        return cls
    return wrapper

def _passive_handler_func(f):
    """ Wrapper to ignore the return value for handler methods dealing with data.

    This is to make it so that passive handlers can't accidentally modify the the data.
    """
    def func(self, input):
        f(self, input)
        return input
    return func

def _passive_handler(store, **kwargs):
    """ Decorator for setting up a passive handler.

    Passive handlers should make no modifications or do any potentially destructive operations on
    connections, they should simply do passive detection of issues.

    NOTE: We currently do not do strict enforcement that passive handlers don't do anything active
    to the connection, we do wrap the standard data handling methods to ignore the return values
    but that is more for convenience than anything else.

    Arguments:
    All arguments are passed to handler(), see handler for argument descriptions.
    """
    def wrapper(cls):
        # Wrap all the traffic methods to ignore the return values from the
        # passive handler
        funcs = ["on_request", "on_inject_request", "on_response",
                 "on_inject_response"]
        for func in funcs:
            f = _passive_handler_func(getattr(cls, func))
            setattr(cls, func, f)
        # Call into the normal wrapper to set cls.passive and add it to the
        # store.
        return handler(store, passive=True, **kwargs)(cls)
    return wrapper

handler.passive = _passive_handler
# Add active for symmetry, currently active is assumed to be the default.
handler.active = handler
