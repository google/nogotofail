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
import os
import glob
import socket
import stat

def find_socket_pid(inode):
    for fd_path in glob.iglob("/proc/*/fd/*"):
        if fd_path.startswith("/proc/self/"):
            continue
        try:
            fd_stat = os.stat(fd_path)
        except OSError:
            # process may have died
            pass
        if (fd_stat.st_mode & stat.S_IFSOCK and
                fd_stat.st_ino == inode):
            break
    else:
        raise ValueError("Socket inode not found")
    pid = int(fd_path.split("/")[2])
    return pid

def get_pid_executable(pid):
    path = os.path.realpath(os.readlink("/proc/%d/exe" % pid))
    return path

def get_pid_cmdline(pid):
    with open("/proc/%d/cmdline" % pid) as f:
        return f.read()

def _match(target_addr, proc_entry, family):
    # Try and match while relaxing target_addr
    if _match_entry(target_addr, proc_entry, family):
        return True
    if _match_entry((None, target_addr[1]), proc_entry, family):
        return True
    return False

def _match_entry(target_addr, proc_entry, family):
    addr = proc_entry[0].decode("hex")
    words = [addr[i*4:(i+1)*4][::-1] for i in range(len(addr)/4)]
    addr = "".join(words)
    if target_addr[0] and socket.inet_ntop(family, addr) != target_addr[0]:
        return False
    if target_addr[1] != -1 and int(proc_entry[1], 16) != target_addr[1]:
        return False
    return True

def find_connection_inode(local_addr, remote_addr):
    families = [socket.AF_INET, socket.AF_INET6]
    files = {socket.AF_INET: "/proc/net/tcp",
             socket.AF_INET6: "/proc/net/tcp6",}
    for family in families:
        fname = files[family]
        with open(fname) as f:
            connection_lines = f.readlines()[1:]
        infos = [conn.strip().split(" ") for conn in connection_lines]
        for info in infos:
            connection_local = info[1].split(":")
            connection_remote = info[2].split(":")
            if (_match(local_addr, connection_local, family) and
                    _match(remote_addr, connection_remote, family)):
                inode = int(info[-8])
                return inode

    raise ValueError("Could not find connection")
