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
from nogotofail.clients.linux import pyblame
import uuid
import argparse
import subprocess
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import logging

logger = logging.getLogger("pyblame")
config = None

def load_config(file):
    config = configparser.SafeConfigParser()
    if config.read([file]):
        return config
    # initialize a blank config
    config.add_section("trusted_servers")
    config.add_section("ids")
    return config

def save_config(config, file):
    with open(file,"w") as f:
        config.write(f)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", help="verbose output", action="store_true",
        default=False)
    parser.add_argument(
        "-A", "--attacks",
        help="Connection attacks to run.",
        nargs="*", metavar="ATTACK",
        action="store", default=None)
    parser.add_argument(
        "-D", "--data",
        help="Data attacks to run.",
        nargs="*", metavar="ATTACK",
        action="store", default=None)
    parser.add_argument(
        "-p", "--probability",
        help="Probability to attack connections",
        action="store", type=float, default=None)
    parser.add_argument(
        "-q", "--quit",
        help="Quit after handshake",
        action="store_true")
    parser.add_argument(
        "-S", "--nossl",
        help="Disable SSL handshake with the blame server",
        action="store_true", default=False)
    parser.add_argument(
        "-l", "--list",
        help="List supported attacks and set attacks",
        action="store_true", default=False)
    parser.add_argument(
        "-c", "--config",
        help="Pyblame config file location(Default to .pyblame.conf)",
        default=".pyblame.conf")
    parser.add_argument(
        "-I", "--device",
        help="Use ID as the device id",
        metavar="ID", action="store")
    parser.add_argument(
        "-P", "--platform",
        help="Use ID as the platform id",
        metavar="ID", action="store")
    parser.add_argument(
        "-w", "--write",
        help="Update configuration file's trusted server and device id",
        action="store_true", default=False)
    parser.add_argument(
        "host",
        help="Host running the blame server to connect to")
    parser.add_argument(
        "port",
        help="Port the blame server is running on")
    return parser.parse_args()

def fingerprint_callback(fingerprint):
    """Called during an SSL handshake with the fingerprint of the key of the remote host.

    Returns if the connection should be trusted.
    """
    # ConfigParser doesn't like :'s
    config_print = fingerprint.replace(":","_")

    if config.has_option("trusted_servers", config_print):
        return True
    response = raw_input("Connect to %s y/N? " % fingerprint)
    if response:
        config.set("trusted_servers", config_print, "trusted")
    return response == "y"

def vulnerability_callback(id, type, server_addr, server_port, applications):
    """Called when a vulnerability is reported
    """
    logger.critical("Vulnerability %s in connection %s to %s:%s by %s"
            % (type, id, server_addr, server_port,
                ", ".join("%s version %s" % (app.application, app.version)
                    for app in applications)))

def client_info_callback(source_port, dest_ip, dest_port):
    """Called when client information is requested.

    Returns a list of pyblame.blame.Application's that are (potentially) responsible
    for the connection or None if no owner can be found.
    """
    try:
        inode = pyblame.util.find_connection_inode((None, source_port), (dest_ip, dest_port))
        pid = pyblame.util.find_socket_pid(inode)
        cmdline = pyblame.util.get_pid_cmdline(pid)
        cmds = cmdline.split("\x00")
        # Use the exe and argv[1] to get a good idea of the program.
        # This handles the python case where argv[0] is python and argv[1] is
        # the script.
        cmd = " ".join(cmds[:2])

        logger.info("Blame request for %s=>%s:%s owner:%s command:%s"
                % (source_port, dest_ip, dest_port, pid, cmd))
        # TODO: Return a meaningful version code?
        return [pyblame.blame.Application(cmd, 0)]

    except ValueError:
        logger.info("Blame request for %s=>%s:%s unknown"
                % (source_port, dest_ip, dest_port))

    return None
def main():
    args = parse_args()
    global config
    config = load_config(args.config)

    LOG_FORMAT = logging.Formatter("%(asctime)-15s [%(levelname)s] %(message)s")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(LOG_FORMAT)
    if args.verbose:
        handler.setLevel(logging.INFO)
    else:
        handler.setLevel(logging.WARNING)
    logger.addHandler(handler)

    if args.device:
        config.set("ids", "device", args.device)
    elif not config.has_option("ids", "device"):
        config.set("ids", "device", str(uuid.uuid4()))
    if args.platform:
        config.set("ids", "platform", args.platform)
    elif not config.has_option("ids", "platform"):
        platform = subprocess.check_output(["uname", "-o", "-s", "-r", "-v"])
        config.set("ids", "platform", platform)
    blame_connection = pyblame.BlameConnection(args.host, args.port,
            ssl=not args.nossl,
            fingerprint_callback=fingerprint_callback,
            install_id=config.get("ids", "device"),
            platform_info=config.get("ids", "platform"),
            probability=args.probability,
            attacks=args.attacks,
            data_attacks=args.data,
            vuln_callback=vulnerability_callback,
            info_callback=client_info_callback)
    try:
        run(blame_connection, args)
    except KeyboardInterrupt:
        pass
    finally:
        if args.write:
            save_config(config, args.config)

def run(blame_connection, args):
    blame_connection.connect()
    blame_connection.handshake()
    if args.list:
        for header, value in blame_connection.resp_headers.iteritems():
            print "%s: %s" % (header, value)
        pass
    if args.quit:
        return
    blame_connection.run()

if __name__ == "__main__":
    main()
