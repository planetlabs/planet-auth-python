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

from planet_auth.planet_legacy.legacy_api_key import FileBackedPlanetLegacyApiKey
from planet_auth.storage_utils import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


class TestLegacyCredential(unittest.TestCase):
    def test_asserts_valid(self):
        under_test = FileBackedPlanetLegacyApiKey(
            api_key=None, api_key_file=tdata_resource_file_path("keys/planet_legacy_test_credential.json")
        )
        under_test.load()
        self.assertEqual("test_legacy_api_key", under_test.legacy_api_key())

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data(None)

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data({"test": "missing required fields"})

    def test_construct_with_literals(self):
        under_test = FileBackedPlanetLegacyApiKey(api_key="test_literal_apikey", jwt="test_literal_jwt")
        self.assertEqual("test_literal_apikey", under_test.legacy_api_key())
        self.assertEqual("test_literal_jwt", under_test.legacy_jwt())

    def test_getters_from_file(self):
        under_test = FileBackedPlanetLegacyApiKey(
            api_key=None, api_key_file=tdata_resource_file_path("keys/planet_legacy_test_credential.json")
        )
        under_test.load()
        self.assertEqual("test_legacy_api_key", under_test.legacy_api_key())
        self.assertEqual("test_legacy_literal_jwt", under_test.legacy_jwt())
