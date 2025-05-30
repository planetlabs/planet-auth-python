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
import shutil
import tempfile
import pathlib

from planet_auth.planet_legacy.legacy_api_key import FileBackedPlanetLegacyApiKey
from planet_auth.planet_legacy.request_authenticator import PlanetLegacyRequestAuthenticator
from planet_auth.storage_utils import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


class PlanetLegacyRequestAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        # Copy because some actions may modify the test data files.
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_dir_path = pathlib.Path(self.tmp_dir.name)

        self.invalid_cred_file = self.tmp_dir_path.joinpath("invalid_test_credential.json")
        shutil.copy(
            tdata_resource_file_path("keys/invalid_test_credential.json"),
            self.invalid_cred_file,
        )

        self.valid_cred_file = self.tmp_dir_path.joinpath("planet_legacy_test_credential.json")
        shutil.copy(
            tdata_resource_file_path("keys/planet_legacy_test_credential.json"),
            self.valid_cred_file,
        )

    def test_pre_request_hook_loads_from_file_happy_path(self):
        under_test = PlanetLegacyRequestAuthenticator(
            planet_legacy_credential=FileBackedPlanetLegacyApiKey(api_key_file=self.valid_cred_file)
        )
        under_test.pre_request_hook()
        self.assertEqual("test_legacy_api_key", under_test._api_key_file.legacy_api_key())

    def test_pre_request_hook_loads_from_file_invalid_throws(self):
        under_test = PlanetLegacyRequestAuthenticator(
            planet_legacy_credential=FileBackedPlanetLegacyApiKey(api_key_file=self.invalid_cred_file)
        )
        with self.assertRaises(FileBackedJsonObjectException):
            under_test.pre_request_hook()

    def test_update_credential_data(self):
        under_test = PlanetLegacyRequestAuthenticator(
            planet_legacy_credential=FileBackedPlanetLegacyApiKey(api_key_file=self.valid_cred_file)
        )
        under_test.pre_request_hook()  # Triggers a JIT load from the file

        orig_data = under_test._credential.data()
        new_data = orig_data.copy()
        new_data["key"] = "utest_new_api_key"

        under_test.update_credential_data(new_credential_data=new_data)
        # Side effect : clobbers the file contents.

        under_test.pre_request_hook()  # Simulate another login event
        self.assertEqual("utest_new_api_key", under_test._token_body)  # Base class view
        self.assertEqual("utest_new_api_key", under_test._api_key_file.legacy_api_key())  # child class view

        # self.assertEqual("TODO?", under_test._token_prefix)

    def test_update_credential(self):
        under_test = PlanetLegacyRequestAuthenticator(
            planet_legacy_credential=FileBackedPlanetLegacyApiKey(api_key_file=self.valid_cred_file)
        )
        under_test.pre_request_hook()  # Triggers a JIT load from the file of the initial credential.

        new_credential = FileBackedPlanetLegacyApiKey(api_key="utest_new_api_key_2")
        under_test.update_credential(new_credential=new_credential)

        under_test.pre_request_hook()  # Simulate another login event
        self.assertEqual("utest_new_api_key_2", under_test._token_body)  # Base class view
        self.assertEqual("utest_new_api_key_2", under_test._api_key_file.legacy_api_key())  # child class view

        # self.assertEqual("TODO?", under_test._token_prefix)
