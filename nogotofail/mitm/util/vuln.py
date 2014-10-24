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
# Vuln types for notify
VULN_TLS_SELF_SIGNED = "selfsigned"
VULN_TLS_INVALID_HOSTNAME = "invalidhostname"
VULN_TLS_ANON_SERVER = "anonserver"
VULN_TLS_CLIENT_HEARTBLEED = "clientheartbleed"
VULN_CLEARTEXT_AUTH = "cleartextauth"
VULN_ANDROID_JAVASCRIPT_RCE = "webviewjsrce"
VULN_EARLY_CCS = "clientearlyccs"
VULN_HTTP = "http"
VULN_CUSTOM_REQUEST_MATCH = "customrequest"
VULN_SSL_STRIP = "sslstrip"
VULN_XMPP_STARTTLS_STRIP = "xmppstarttlsstrip"
