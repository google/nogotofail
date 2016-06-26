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
import copy

from nogotofail.mitm.blame import Server as AppBlameServer
from nogotofail.mitm.connection import Server, RedirectConnection, SocksConnection, TproxyConnection
from nogotofail.mitm.connection import handlers
from nogotofail.mitm.connection.handlers import preconditions
from nogotofail.mitm.looper import MitmLoop
from nogotofail.mitm.util import routing, extras

LOG_FORMAT = logging.Formatter("%(asctime)-15s [%(levelname)s] %(message)s")
EVENT_FORMAT = logging.Formatter("%(message)s")
logger = logging.getLogger("nogotofail.mitm")
event_logger = logging.getLogger("event")
traffic_logger = logging.getLogger("traffic")

# PII configuration file section names
SECTION_MITM = "nogotofail.mitm"
SECTION_PII_ITEMS = "nogotofail.pii"

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
        if not ssl_handlers:
            return None
        if random.random() < attack_prob:
            return random.choice(ssl_handlers)
        return None
    return attack_selector


def build_data_selector(default_handlers, MITM_all, prob_attack=0.5):
    internal = handlers.data.handlers.internal

    def data_selector(connection, app_blame):
        if not MITM_all and not app_blame.client_available(
            connection.client_addr):
            return internal + []
        # Figure out our possible handlers
        client_info = app_blame.clients.get(connection.client_addr)
        client_info = client_info.info if client_info else None
        if client_info:
            handlers = client_info.get("Data-Attacks", default_handlers)
            attack_prob = client_info.get("Attack-Probability", prob_attack)
        else:
            handlers = default_handlers
            attack_prob = prob_attack

        # Split handlers into passive/active
        passive, active = [], []
        for handler in handlers:
            (active, passive)[handler.passive].append(handler)

        # 1-p chance of not using any data attacks on a connection.
        if random.random() >= attack_prob:
            active = []

        return internal + passive + active
    return data_selector

def get_client_pii_items():

    def client_pii_items(connection, app_blame):
        pii_items = {}
        try:
            if (not app_blame.client_available(connection.client_addr)):
                return internal + []
            # Figure out our possible handlers
            client_info = app_blame.clients.get(connection.client_addr)
            client_info = client_info.info if client_info else None
            if client_info:
                pii_items = client_info.pii_store.pii_items_plaintext
            return pii_items
        except Exception as e:
            logger.exception(str(e))
            return {}

def get_client_pii_location():

    def client_pii_location(connection, app_blame):
        pii_location = {}
        try:
            if (not app_blame.client_available(connection.client_addr)):
                return internal + []
            # Figure out our possible handlers
            client_info = app_blame.clients.get(connection.client_addr)
            client_info = client_info.info if client_info else None
            if client_info:
                pii_location = client_info.pii_store.pii_location
                # client_info["PII-Location"]
            return pii_location
        except Exception as e:
            logger.exception(str(e))
            return {}

def build_server(port, blame, selector, ssl_selector, data_selector, block,
    ipv6, cls):
    return Server(port, blame, handler_selector=selector,
                  ssl_handler_selector=ssl_selector,
                  data_handler_selector=data_selector,
                  block_non_clients=block,
                  ipv6=ipv6,
                  connection_class=cls)


def build_blame(port, cert, probability, attacks, data_attacks, config_pii):
    return AppBlameServer(port, cert, probability, attacks, data_attacks,
        config_pii)

def set_redirect_rules(args):
    port = args.port
    ipv6 = args.ipv6
    routing.enable_redirect_rules(port, ipv6=ipv6)
    atexit.register(routing.disable_redirect_rules, ipv6=ipv6)

def set_tproxy_rules(args):
    port = args.port
    ipv6 = args.ipv6
    routing.enable_tproxy_rules(port, ipv6=ipv6)
    atexit.register(routing.disable_tproxy_rules, ipv6=ipv6)

# Traffic capture modes
Mode = collections.namedtuple("Mode", ["cls", "setup", "description"])
modes = {
        "redirect": Mode(RedirectConnection,
            set_redirect_rules,
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
        config = {}
        configBase = ConfigParser.SafeConfigParser()
        configBase.read(args.config)
        has_mitm_section = configBase.has_section(SECTION_MITM)
        has_pii_items_section = configBase.has_section(SECTION_PII_ITEMS)

        config_copy = copy.copy(configBase)
        # Check if the "nogotofail.mitm" section exists.
        if has_mitm_section:
            config_mitm = dict(config_copy.items(SECTION_MITM))
            if "attacks" in config_mitm:
                config_mitm["attacks"] = config_mitm["attacks"].split(" ")
            if "data" in config_mitm:
                config_mitm["data"] = config_mitm["data"].split(" ")
            config = config_mitm
        # Check if the "nogotofail.pii" section exists.
        if has_pii_items_section:
            config_pii_items = dict(config_copy.items(SECTION_PII_ITEMS))
            config["pii_items"] = config_pii_items
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
        "-p", "--probability", help="probably of attacking a SSL connection",
        action="store", type=float, default=0.5)
    parser.add_argument(
        "-d", "--debug", help="Print debug output", action="store_true",
        default=False)
    parser.add_argument(
        "-b", "--bridge", help="Bridge connections from hosts without a client",
        action="store_false", default=True, dest="all")
    parser.add_argument(
        "-l", "--logfile", help="Log output file", action="store")
    parser.add_argument(
        "-e", "--eventlogfile", help="Event log output file", action="store")
    parser.add_argument(
        "-t", "--trafficfile", help="Traffic output file", action="store")
    parser.add_argument(
        "-q", "--quiet",
        help="Quiet output. Only prints important messages.",
        action="store_true", default=False)
    parser.add_argument(
        "--port", help="Port to bind the mitm to", action="store",
        type=int, default=8080)
    parser.add_argument(
        "--cport", help="Port to listen for nogotofail clients on", action="store",
        type=int, default=8443)
    parser.add_argument(
        "-6", "--ipv6",
        help=("Route IPv6 traffic. "
        "Requires support for ip6tables NAT redirect when in redirect mode (iptables > 1.4.17)"),
        default=False, action="store_true")

    parser.add_argument(
        "--fns1", help="***** Nogotofail functions *****************************",
        action="store_true", default=False)
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
        "--block", help="Block connections with unknown blame info",
        action="store_true", default=False)
    parser.add_argument(
        "--mode", help="Traffic capture mode. Options are " + ", ".join(modes.keys()),
        choices=modes, metavar="MODE", action="store", default=default_mode)
    parser.add_argument(
        "-x", "--extrasdir", help="Directory containing extra files required by handlers",
        default = "./")
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
    elif args.quiet:
        handler.setLevel(logging.WARNING)
    else:
        handler.setLevel(logging.INFO)
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
    extras.extras_dir = args.extrasdir

    selector = build_selector(args.all)
    attack_cls = [handlers.connection.handlers.map[name]
                  for name in args.attacks]
    attack_cls = preconditions.filter_preconditions(attack_cls, logger)
    data_cls = [handlers.data.handlers.map[name] for name in args.data]
    data_cls = preconditions.filter_preconditions(data_cls, logger)
    ssl_selector = build_ssl_selector(attack_cls, args.probability, args.all)
    data_selector = build_data_selector(data_cls, args.all,
                                        prob_attack=args.probability)
    # Build PII collection.
    server_config_pii = {}
    server_config_pii["items"] = args.pii_items

    logger.info("Starting...")

    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
        mode = modes[args.mode]
        if mode.setup:
            mode.setup(args)
        blame = (
            build_blame(
                args.cport, args.serverssl, args.probability, attack_cls,
                data_cls, server_config_pii))
        server = (
            build_server(
                args.port, blame, selector, ssl_selector,
                data_selector, args.block, args.ipv6, mode.cls))
        blame.start_listening()
        server.start_listening()
        # Run the main loop
        looper = MitmLoop(blame, server)
        looper.run()
    except KeyboardInterrupt:
        server.shutdown()
        blame.shutdown()
    except Exception as e:
        logger.exception("Uncaught top level exception!")
        logger.fatal("EXITING")

if __name__ == "__main__":
    run()
