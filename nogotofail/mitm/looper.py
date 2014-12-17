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
import select

class MitmLoop(object):
    """Handles the main loop for running nogotofail.mitm."""
    def __init__(self, blame_server, connection_server):
        self._servers = [blame_server, connection_server]
    def run(self, only_once=False, timeout=5):
        """Run the MitmLoop.
        This calls select on all active sockets and dispatches the resulting sockets to the
        connection and blame servers.

        Keyword arguments:
        only_once -- run the select loop only once instead of forever (default False)
        timeout -- the timeout for select in seconds (default 5)
        """
        servers = self._servers
        while True:
            # Build the map of fds we are actively selecting over. This changes
            # from pass to pass and connections come and go and change state.
            fds = {server: set([sock for fds in server.select_fds for sock in fds])
                    for server in servers}
            r, w, x = [set().union(*l) for l in zip(*[server.select_fds for server in servers])]
            r, w, x = select.select(r, w, x, timeout)
            # Call on_select with all the fds we found from each server.
            for server in servers:
                filter_func = lambda fd: fd in fds[server]
                server.on_select(filter(filter_func, r),
                        filter(filter_func, w),
                        filter(filter_func, x))

            if only_once:
                return

