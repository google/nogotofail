r'''
Copyright 2015 Google Inc. All rights reserved.

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

class TlsNotEnoughDataError(Exception):
    """Error in TLS parsing where the TLS record is so far valid but incomplete"""
    pass

class TlsRecordIncompleteError(TlsNotEnoughDataError):
    """Error for when a TLS Record appears valid but is not enough data is present to parse
    the record"""
    def __init__(self, data_available, record_size):
        self.data_available = data_available
        self.record_size = record_size

class TlsMessageFragmentedError(TlsNotEnoughDataError):
    """Error for when not enough data is present to parse a TLS message because of
    fragmentation"""
    def __init__(self, fragment_data, data_consumed):
        self.fragment_data = fragment_data
        self.data_consumed = data_consumed
