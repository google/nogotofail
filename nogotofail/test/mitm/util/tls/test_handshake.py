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
import unittest
from nogotofail.mitm.util import tls

# Basic client hello from `openssl s_client -tls1_2 -cipher HIGH`
BASIC_HELLO = ("FgMBASIBAAEeAwOVqPajcw+kjqqu6OY0g/k/UqYSjwdXHdiYwhfn+ZpNPgAAiMAwwCzAKMAkwBTA\n"
               "CgCjAJ8AawBqADkAOACIAIfAGQCnAG0AOgCJwDLALsAqwCbAD8AFAJ0APQA1AITAEsAIABYAE8AX\n"
               "ABvADcADAArAL8ArwCfAI8ATwAkAogCeAGcAQAAzADIARQBEwBgApgBsADQARsAxwC3AKcAlwA7A\n"
               "BACcADwALwBBAP8BAABtAAsABAMAAQIACgA0ADIADgANABkACwAMABgACQAKABYAFwAIAAYABwAU\n"
               "ABUABAAFABIAEwABAAIAAwAPABAAEQAjAAAADQAgAB4GAQYCBgMFAQUCBQMEAQQCBAMDAQMCAwMC\n"
               "AQICAgMADwABAQ==\n").decode("base64")


# BASIC_HELLO split into two fragments
FRAGMENTED_BASIC_HELLO = (
        "FgMBADIBAAEeAwOVqPajcw+kjqqu6OY0g/k/UqYSjwdXHdiYwhfn+ZpNPgAAiMAwwCzAKMAkwBYD\n"
        "AQDwFMAKAKMAnwBrAGoAOQA4AIgAh8AZAKcAbQA6AInAMsAuwCrAJsAPwAUAnQA9ADUAhMASwAgA\n"
        "FgATwBcAG8ANwAMACsAvwCvAJ8AjwBPACQCiAJ4AZwBAADMAMgBFAETAGACmAGwANABGwDHALcAp\n"
        "wCXADsAEAJwAPAAvAEEA/wEAAG0ACwAEAwABAgAKADQAMgAOAA0AGQALAAwAGAAJAAoAFgAXAAgA\n"
        "BgAHABQAFQAEAAUAEgATAAEAAgADAA8AEAARACMAAAANACAAHgYBBgIGAwUBBQIFAwQBBAIEAwMB\n"
        "AwIDAwIBAgICAwAPAAEB\n").decode("base64")

class TestClientHelloParsing(unittest.TestCase):

    def check_basic_hello_record(self, record):
        # Verify parsing was successful
        self.assertIsNotNone(record, "parse_tls failed")

        # Check the record is sane
        self.assertEqual(record.version.major, 3)
        self.assertEqual(record.version.minor, 1)
        self.assertEqual(record.content_type, record.CONTENT_TYPE.HANDSHAKE)
        self.assertEqual(len(record.messages), 1)

        # Check the HandshakeMessage
        message = record.messages[0]
        self.assertIsInstance(message, tls.types.HandshakeMessage)
        self.assertEqual(message.type, message.TYPE.CLIENT_HELLO)

        # Check the ClientHello itself
        hello = message.obj
        self.assertIsInstance(hello, tls.types.ClientHello)
        self.assertEqual(hello.version.major, 3)
        self.assertEqual(hello.version.minor, 3)
        self.assertEqual(hello.session_id, [])
        self.assertEqual(hello.random.bytes,
                "730fa48eaaaee8e63483f93f52a6128f07571dd898c217e7f99a4d3e".decode("hex"))
        # TODO: Check that the contents are correct/correct order
        self.assertEqual(len(hello.ciphers), 68)
        self.assertEqual(len(hello.extensions), 5)
        for key in [35, 10, 11, 13, 15]:
            self.assertTrue(key in hello.extensions)

    def test_parse_basic_hello(self):
        record, remaining = tls.parse_tls(BASIC_HELLO)
        self.assertIsNotNone(record)
        self.assertEquals(remaining, "")
        self.check_basic_hello_record(record)

    def test_parse_basic_hello_extra(self):
        extra_bytes = "\x11\x22\x33\x44"
        record, remaining = tls.parse_tls(BASIC_HELLO + extra_bytes)
        self.assertIsNotNone(record)
        self.assertEquals(remaining, extra_bytes)
        self.check_basic_hello_record(record)

    def test_fragmented_basic_hello(self):
        record, remaining = tls.parse_tls(FRAGMENTED_BASIC_HELLO)
        self.assertIsNotNone(record)
        self.assertEquals(remaining, "")
        self.check_basic_hello_record(record)

    def test_fragmenting(self):
        record, remaining = tls.parse_tls(BASIC_HELLO)
        self.assertIsNotNone(record)
        self.assertEquals(remaining, "")
        # Fragment on purpose
        bytes = record.to_bytes(max_fragment_size=50)
        # sanity check this parses back out
        parsed_rec, remaining = tls.parse_tls(bytes)
        self.assertIsNotNone(parsed_rec)
        self.assertEqual(remaining, "")
        self.check_basic_hello_record(parsed_rec)

        # Now check that they got split by parsing for only one record
        with self.assertRaises(tls.types.TlsNotEnoughDataError):
            tls.types.TlsRecord.from_stream(bytes)

if __name__ == "__main__":
    unittest.main()
