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

from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.storage_utils import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


class TestOidcCredential(unittest.TestCase):
    def test_asserts_valid(self):
        under_test = FileBackedOidcCredential(
            data=None, credential_file=tdata_resource_file_path("keys/oidc_test_credential.json")
        )
        under_test.load()
        self.assertIsNotNone(under_test.data())

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data(None)

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data({"test": "missing all required fields"})

    def test_getters(self):
        under_test = FileBackedOidcCredential(
            data=None, credential_file=tdata_resource_file_path("keys/oidc_test_credential.json")
        )
        under_test.load()
        self.assertEqual("_dummy_access_token_", under_test.access_token())
        self.assertEqual("_dummy_refresh_token_", under_test.refresh_token())
        self.assertEqual("_dummy_id_token_", under_test.id_token())
