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
#! /usr/bin/env python

import time
import random
import logging
import logging.handlers
import argparse
import threading
import textwrap
import atexit
import subprocess
import signal
import ConfigParser
import collections
import sys

from nogotofail.mitm.connection import Server, RedirectConnection, SocksConnection, TproxyConnection
from nogotofail.mitm.blame import Server as AppBlameServer
from nogotofail.mitm.connection import handlers
from nogotofail.mitm.util import get_interface_addresses

LOG_FORMAT = logging.Formatter("%(asctime)-15s [%(levelname)s] %(message)s")
EVENT_FORMAT = logging.Formatter("%(message)s")
logger = logging.getLogger("nogotofail.mitm")
event_logger = logging.getLogger("event")
traffic_logger = logging.getLogger("traffic")


def build_selector(MITM_all=False):
    def handler_selector(connection, app_blame):
        if not MITM_all and not app_blame.client_available(
            connection.client_addr):
            return handlers.base.BaseConnectionHandler
        return handlers.connection.LoggingHandler
    return handler_selector


def build_ssl_selector(default_ssl_handlers, prob_MITM=0.5, MITM_all=False):
    def attack_selector(connection, client_hello, app_blame):
        if not MITM_all and not app_blame.client_available(
            connection.client_addr):
            return None
        client_info = app_blame.clients.get(connection.client_addr)
        client_info = client_info.info if client_info else None
        if client_info:
            attack_prob = client_info.get("Attack-Probability", prob_MITM)
            ssl_handlers = client_info.get("Attacks", default_ssl_handlers)
        else:
            attack_prob = prob_MITM
            ssl_handlers = default_ssl_handlers
        if random.random() < attack_prob:
            return random.choice(ssl_handlers)
        return None
    return attack_selector


def build_data_selector(default_handlers, MITM_all):
    internal = handlers.data.handlers.internal

    def data_selector(connection, app_blame):
        if not MITM_all and not app_blame.client_available(
            connection.client_addr):
            return internal + []
        client_info = app_blame.clients.get(connection.client_addr)
        client_info = client_info.info if client_info else None
        if client_info:
            handlers = client_info.get("Data-Attacks", default_handlers)
        else:
            handlers = default_handlers
        return internal + handlers
    return data_selector


def build_server(port, blame, selector, ssl_selector, data_selector, block, ipv6, cls):
    return Server(port, blame, handler_selector=selector,
                  ssl_handler_selector=ssl_selector,
                  data_handler_selector=data_selector,
                  block_non_clients=block,
                  ipv6=ipv6,
                  connection_class=cls)


def build_blame(cert, probability, attacks, data_attacks):
    return AppBlameServer(8443, cert, probability, attacks, data_attacks)

# Below are the rules for setting up/tearing down iptables and ip rules for
# geting traffic to nogotofail.mitm. TODO: Clean this up, it is really ugly right now.

def set_tproxy_iprules(enable=True, ipv6=False, log=True, mark=100):
    table_cmd = "ip %s route %s local default dev lo table %d"
    rule_cmd = "ip %s rule %s fwmark %d table %d"
    ip_action = "add" if enable else "del"

    commands = [table_cmd % ("-4", ip_action, mark)]
    commands += [rule_cmd % ("-4", ip_action, mark, mark)]
    if ipv6:
        commands += [table_cmd % ("-6", ip_action, mark)]
        commands += [rule_cmd % ("-6", ip_action, mark, mark)]
    executed = []
    try:
        for command in commands:
            _ = subprocess.check_output(
                command, stderr=subprocess.STDOUT, shell=True)
            executed.append(command)
    except Exception:
        # Undo any rules we added
        if enable:
            for command in executed:
                try:
                    _ = subprocess.check_output(
                        command.replace("add", "del"),
                        stderr=subprocess.STDOUT, shell=True)
                except:
                    pass
        if log:
            logger.warning("Failed to execute ip command")
        return
    if enable:
        atexit.register(set_tproxy_iprules, enable=False, ipv6=ipv6, mark=mark, log=False)

def set_tproxy_rules(args, enable=True, log=True, mark=100):
    """Setup iptables tproxy rules to redirect traffic to nogotofail.mitm."""
    port = args.port
    ipv6 = args.ipv6

    set_tproxy_iprules(enable, ipv6, log, mark)

    command_v4 = "iptables"
    command_v6 = "ip6tables"
    return_cmd = "%s -t mangle %s PREROUTING -p tcp -m socket --jump RETURN"
    return_cmd2 = "%s -t mangle %s PREROUTING -p tcp -d %s --jump RETURN"
    redirect_cmd = "%s -t mangle %s PREROUTING -p tcp -j TPROXY --tproxy-mark %d --on-port %d"

    action = "-A" if enable else "-D"
    v4_addrs, v6_addrs = get_interface_addresses()

    commands = [return_cmd2 % (command_v4, action, v4_addr)
                for v4_addr in v4_addrs]
    commands += [return_cmd % (command_v4, action)]
    if ipv6:
        commands += [return_cmd % (command_v6, action)]
        commands += [return_cmd2 %
                     (command_v6, action, v6_addr) for v6_addr in v6_addrs]
    # Generate commands to grab all other traffic
    commands += [redirect_cmd % (command_v4, action, mark, port)]
    if ipv6:
        commands += [redirect_cmd % (command_v6, action, mark, port)]
    executed = []
    try:
        for command in commands:
            _ = subprocess.check_output(
                command, stderr=subprocess.STDOUT, shell=True)
            executed.append(command)
    except Exception:
        # Undo any rules we added
        if enable:
            for command in executed:
                try:
                    _ = subprocess.check_output(
                        command.replace("-A", "-D"),
                        stderr=subprocess.STDOUT, shell=True)
                except:
                    pass
        if log:
            logger.warning("Failed to execute iptables command")
        return
    if enable:
        atexit.register(set_tproxy_rules, args, enable=False)

def set_iptables_rules(args, enable=True, log=True):
    """Setup iptables redirect rules to redirect traffic to nogotofail.mitm.

    This tries and routes all traffic not destinated for a local address
    to nogotofail.mitm. Since redirect rules can only live in PREROUTING we have
    to do a best guess at what is through traffic ourselves.
    """
    port = args.port
    ipv6 = args.ipv6

    command_v4 = "iptables"
    command_v6 = "ip6tables"
    return_cmd = "%s -t nat %s PREROUTING -p tcp -d %s --jump RETURN"
    redirect_cmd = "%s -t nat %s PREROUTING -p tcp -j REDIRECT --to-ports %s"
    action = "-A" if enable else "-D"
    v4_addrs, v6_addrs = get_interface_addresses()
    # Generate iptables commands for skipping traffic bound for this device
    commands = [return_cmd % (command_v4, action, v4_addr)
                for v4_addr in v4_addrs]
    if ipv6:
        commands += [return_cmd %
                     (command_v6, action, v6_addr) for v6_addr in v6_addrs]
    # Generate commands to grab all other traffic
    commands += [redirect_cmd % (command_v4, action, port)]
    if ipv6:
        commands += [redirect_cmd % (command_v6, action, port)]
    executed = []
    try:
        for command in commands:
            _ = subprocess.check_output(
                command, stderr=subprocess.STDOUT, shell=True)
            executed.append(command)
    except Exception:
        if log:
            logger.warning("Failed to execute iptables command")
        return
    if enable:
        atexit.register(set_iptables_rules, args, enable=False)

# Traffic capture modes
Mode = collections.namedtuple("Mode", ["cls", "setup", "description"])
modes = {
        "redirect": Mode(RedirectConnection,
            set_iptables_rules,
            "Use Iptables REDIRECT to route traffic. Ipv6 support is limited in this mode."),
        "tproxy": Mode(TproxyConnection,
            set_tproxy_rules,
            "Use iptables TPROXY/mark to route traffic"),
        "socks": Mode(SocksConnection,
            None,
            "Listen as a SOCKS server to route traffic"),
        }

default_mode = "tproxy"


def parse_args():
    all_attacks = handlers.connection.handlers.map.keys()
    default_attacks = [h.name for h in handlers.connection.handlers.default]

    all_data = handlers.data.handlers.map.keys()
    default_data = [h.name for h in handlers.data.handlers.default]

    # Check for a config file
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-c", "--config")
    args, argv = parser.parse_known_args()
    if args.config:
        config = ConfigParser.SafeConfigParser()
        config.read(args.config)
        config = dict(config.items("nogotofail.mitm"))
        if "attacks" in config:
            config["attacks"] = config["attacks"].split(" ")
        if "data" in config:
            config["data"] = config["data"].split(" ")
    else:
        config = {}

    modes_str = ("Supported modes:\n" +
                   "\n".join(["\n\t".join(
                       textwrap.wrap("%s - %s" % (name, mode.description), 80))
                              for name, mode in modes.items()]))
    attacks_str = ("Supported attacks:\n" +
                   "\n".join(["\n\t".join(
                       textwrap.wrap("%s - %s" % (name, handler.description), 80))
                              for name, handler in handlers.connection.handlers.map.items()]))
    data_str = ("Supported data handlers:\n" +
                "\n".join(["\n\t".join(
                    textwrap.wrap("%s - %s" % (name, handler.description), 80))
                           for name, handler in handlers.data.handlers.map.items()]))
    epilog = "\n\n".join([modes_str, attacks_str, data_str])
    parser = (
        argparse.ArgumentParser(
            formatter_class=argparse.RawTextHelpFormatter, epilog=epilog))
    # Technically --config is eaten by the previous parser, this is just to make
    # it show up in --help.
    parser.add_argument(
        "-c", "--config", help="Configuration file", metavar="FILE")
    parser.add_argument(
        "-v", "--verbose", help="verbose output", action="store_true",
        default=False)
    parser.add_argument(
        "-p", "--probability", help="probably of attacking a SSL connection",
        action="store", type=float, default=0.5)
    parser.add_argument(
        "-d", "--debug", help="Print debug output", action="store_true",
        default=False)
    parser.add_argument(
        "-a", "--all", help="MITM all clients", action="store_true",
        default=False)
    parser.add_argument(
        "-l", "--logfile", help="Log output file", action="store")
    parser.add_argument(
        "-e", "--eventlogfile", help="Event log output file", action="store")
    parser.add_argument(
        "-t", "--trafficfile", help="Traffic output file", action="store")
    parser.add_argument(
        "-q", "--quiet",
        help="Quiet output. Only prints MITM success messages",
        action="store_true", default=False)
    parser.add_argument(
        "--port", help="Port to bind the connection to", action="store",
        type=int, default=8080)
    parser.add_argument(
        "-6", "--ipv6",
        help=("Route IPv6 traffic. "
        "Requires support for ip6tables NAT redirect when in redirect mode (iptables > 1.4.17)"),
        default=False, action="store_true")
    parser.add_argument(
        "-A", "--attacks",
        help="Connection attacks to run. Supported attacks are " +
        ", ".join(all_attacks),
        choices=handlers.connection.handlers.map, nargs="+", metavar="ATTACK",
        action="store", default=default_attacks)
    parser.add_argument(
        "-D", "--data",
        help="Data attacks to run. Supported attacks are " +
        ", ".join(all_data), choices=handlers.data.handlers.map, nargs="+",
        metavar="ATTACK", action="store", default=default_data)
    parser.add_argument(
        "--serverssl", help="Run the app blame server with SSL using PEMFILE",
        metavar="PEMFILE", action="store")
    parser.add_argument(
        "-b", "--block", help="Block connections with unknown blame info",
        action="store_true", default=False)
    parser.add_argument(
        "--mode", help="Traffic capture mode. Options are " + ", ".join(modes.keys()),
        choices=modes, metavar="MODE", action="store", default=default_mode)
    parser.set_defaults(**config)
    return parser.parse_args(argv)

def sigterm_handler(num, frame):
    """Gracefully exit on a SIGTERM.
    atexit isn't called on a SIGTERM, causing our cleanup code not to be called.
    instead catch the sigterm and call sys.exit, which will call our cleanup
    """
    sys.exit()

def setup_logging(args):
    """Setup logging handlers based on arguments
    """
    handler = logging.StreamHandler()
    handler.setFormatter(LOG_FORMAT)
    if args.debug:
        handler.setLevel(logging.DEBUG)
    elif args.verbose:
        handler.setLevel(logging.INFO)
    elif args.quiet:
        handler.setLevel(logging.CRITICAL)
    else:
        handler.setLevel(logging.WARNING)
    logger.addHandler(handler)

    if args.logfile:
        handler = logging.handlers.WatchedFileHandler(args.logfile)
        handler.setFormatter(LOG_FORMAT)
        if args.debug:
            handler.setLevel(logging.DEBUG)
        else:
            handler.setLevel(logging.INFO)
        logger.addHandler(handler)

    if args.eventlogfile:
        handler = logging.handlers.WatchedFileHandler(args.eventlogfile)
    else:
        handler = logging.NullHandler()
    handler.setLevel(logging.INFO)
    event_logger.addHandler(handler)
    event_logger.setLevel(logging.INFO)

    if args.trafficfile:
        handler = logging.handlers.WatchedFileHandler(args.trafficfile)
    else:
        handler = logging.NullHandler()
    handler.setLevel(logging.INFO)
    traffic_logger.addHandler(handler)
    traffic_logger.setLevel(logging.INFO)

    logger.setLevel(logging.DEBUG)

def run():

    args = parse_args()
    setup_logging(args)

    selector = build_selector(args.all)
    attack_cls = [handlers.connection.handlers.map[name]
                  for name in args.attacks]
    data_cls = [handlers.data.handlers.map[name] for name in args.data]
    ssl_selector = build_ssl_selector(attack_cls, args.probability, args.all)
    data_selector = build_data_selector(data_cls, args.all)

    logger.info("Starting...")
    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
        mode = modes[args.mode]
        if mode.setup:
            mode.setup(args)
        blame = (
            build_blame(
                args.serverssl, args.probability, attack_cls,
                data_cls))
        server = (
            build_server(
                args.port, blame, selector, ssl_selector,
                data_selector, args.block, args.ipv6, mode.cls))
        blame.start()
        server.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
        blame.shutdown()

if __name__ == "__main__":
    run()
