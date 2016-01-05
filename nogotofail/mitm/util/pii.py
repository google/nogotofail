r'''
Copyright 2016 Google Inc. All rights reserved.

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

import base64
import urllib

# PII log entry caveats
CAVEAT_PII_QRY_STRING = "PII-QueryString"
CAVEAT_PII_HEADER = "PII-Header"
CAVEAT_PII_MSG_BODY = "PII-Message-Body"


class PiiStore(object):
    """ Holds PII items supplied and methods for detecting these in
        HTTP content
    """

    # Dictionary contains specified pii items and base64 and url-encoded
    # variations of these.
    _pii_items = {}
    # Dictionary holds plain text version of pii items.
    _pii_items_plaintext = {}
    # Dictionary containing the device's location.
    _pii_location = {}

    def __init__(self, pii_items, pii_location):
        self._pii_items_plaintext = pii_items
        pii_items_plaintext = pii_items
        pii_items_base64 = {}
        pii_items_urlencoded = {}
        # Create base64 dictionary of PII items
        for id_key, id_value in pii_items_plaintext.iteritems():
            # Add a base64 version of ID to dictionary
            pii_items_base64[id_key + " (base64)"] = base64.b64encode(id_value)
        # Create url encoded dictionary of PII identifiers
        for id_key, id_value in pii_items_plaintext.iteritems():
            # Add a url encoded version of ID to dictionary if its different
            # from the plain text version
            id_value_urln = urllib.quote_plus(id_value)
            if (id_value != id_value_urln):
                pii_items_urlencoded[id_key + " (url encoded)"] = id_value_urln
        # Combine PII items and variations into a single dictionary.
        self._pii_items = {k: v for d in
            (pii_items_plaintext, pii_items_base64, pii_items_urlencoded)
            for k, v in d.iteritems()}
        # Assign device location to dictionary.
        self._pii_location["longitude"] = pii_location["longitude"]
        self._pii_location["latitude"] = pii_location["latitude"]

    @property
    def pii_items(self):
        return self._pii_items

    @property
    def pii_items_plaintext(self):
        return self._pii_items_plaintext

    @property
    def pii_location(self):
        return self._pii_location

    def detect_pii_items(self, http_string):
        """ Method searches for PII items within a HTTP string
            i.e. query string, headers, message body
        """
        pii_items_found = []
        # Search query string for pii items.
        if self._pii_items:
            pii_items_found = [k for k, v in
                self._pii_items.iteritems() if v in http_string]
        return pii_items_found

    def detect_pii_location(self, http_string):
        """ Method searches for location (longitude/latitude) within a
        HTTP string i.e. query string, headers, message body
        """
        pii_location_found = []
        if self._pii_location:
            longitude = self._pii_location["longitude"]
            latitude = self._pii_location["latitude"]
            if (longitude in http_string and latitude in http_string):
                pii_location_found.append(longitude)
                pii_location_found.append(latitude)
        return pii_location_found
