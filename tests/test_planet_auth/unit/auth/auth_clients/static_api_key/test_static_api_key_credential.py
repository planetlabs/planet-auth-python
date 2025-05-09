# Copyright 2024-2025 Planet Labs PBC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from planet_auth.static_api_key.static_api_key import FileBackedApiKey
from planet_auth.storage_utils import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


class TestStaticApiKeyCredential(unittest.TestCase):
    def test_asserts_valid(self):
        under_test = FileBackedApiKey(
            api_key=None, api_key_file=tdata_resource_file_path("keys/static_api_key_test_credential.json")
        )
        under_test.load()
        self.assertEqual("test_api_key", under_test.api_key())
        self.assertEqual("test_prefix", under_test.bearer_token_prefix())

        under_test = FileBackedApiKey(
            api_key=None, api_key_file=tdata_resource_file_path("keys/invalid_test_credential.json")
        )
        with self.assertRaises(FileBackedJsonObjectException):
            under_test.load()
        self.assertIsNone(under_test.data())

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data(None)
        self.assertIsNone(under_test.data())

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data({"bearer_token_prefix": "api_key is missing"})
        self.assertIsNone(under_test.data())

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data({"api_key": "bearer_token_prefix is missing"})
        self.assertIsNone(under_test.data())

    def test_construct_with_literals(self):
        under_test = FileBackedApiKey(api_key="test_literal_apikey", prefix="test_literal_prefix")
        self.assertEqual("test_literal_apikey", under_test.api_key())
        self.assertEqual("test_literal_prefix", under_test.bearer_token_prefix())

    def test_getters(self):
        under_test = FileBackedApiKey(
            api_key=None, api_key_file=tdata_resource_file_path("keys/static_api_key_test_credential.json")
        )
        under_test.load()
        self.assertEqual("test_api_key", under_test.api_key())
        self.assertEqual("test_prefix", under_test.bearer_token_prefix())
