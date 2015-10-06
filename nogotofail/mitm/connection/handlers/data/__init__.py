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

from nogotofail.mitm.connection.handlers import store
from data import DataHandler

handlers = store.HandlerStore()

from report import ClientReportDetection
from log import RawTrafficLogger
from mitm import SslMitmHandler
from http import *
from imap import *
from smtp import *
from xmpp import *
from custom import CustomRequestDetection
from ssl import *
