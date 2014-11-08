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
import psutil


def _match_connection(connection, local_addr, remote_addr, relaxed=False):
    return (connection.raddr and
            connection.laddr and
            remote_addr[0] == connection.raddr[0] and
            remote_addr[1] == connection.raddr[1] and
            (local_addr[0] == connection.laddr[0] or relaxed) and
            local_addr[1] == connection.laddr[1])


def find_connection_owner(local_addr, remote_addr, relaxed=False):
    # Walk through proccesses instead of using psutil.net_connections
    # becuse net_connections requires root on OSX.
    for proc in psutil.process_iter():
        try:
            # Work around API change in 2.0.0
            if psutil.version_info[0] < 2:
                connections = proc.get_connections(kind="tcp")
            else:
                connections = proc.connections(kind="tcp")

            for connection in connections:
                if _match_connection(connection, local_addr, remote_addr, relaxed=relaxed):
                    return proc

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # If we failed to match try relaxing the source IP check, what the MiTM
    # sees as the source addr might not match what we see.
    if not relaxed:
        return find_connection_owner(local_addr, remote_addr, relaxed=True)
    raise ValueError("Could not find connection owner")

