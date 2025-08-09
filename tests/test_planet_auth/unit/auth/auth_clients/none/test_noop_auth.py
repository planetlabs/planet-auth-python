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

import pathlib
import unittest

from planet_auth.none.noop_auth import NoOpCredential, NoOpAuthClientConfig, NoOpAuthClient

TEST_CREDENTIAL_FILE = "/some/path/that/does/not/exist.json"


class NoOpCredentialTest(unittest.TestCase):
    def test_noop_cred(self):
        under_test = NoOpCredential()
        under_test.set_path(TEST_CREDENTIAL_FILE)

        under_test.load()  # Should do nothing.

        under_test.save()
        self.assertFalse(pathlib.Path(TEST_CREDENTIAL_FILE).exists())


class NoOpAuthClientTest(unittest.TestCase):
    def setUp(self):
        self.under_test = NoOpAuthClient(NoOpAuthClientConfig())

    def test_login(self):
        cred = self.under_test.login()
        self.assertIsInstance(cred, NoOpCredential)

    def test_refresh(self):
        cred = self.under_test.refresh("refresh_token", requested_scopes=[])
        self.assertIsInstance(cred, NoOpCredential)

    def test_validate_access_token(self):
        results = self.under_test.validate_access_token_remote("test_token")
        self.assertEqual({}, results)

    def test_validate_access_token_local(self):
        results = self.under_test.validate_access_token_local("test_token", "test_audience")
        self.assertEqual({}, results)

    def test_validate_id_token(self):
        results = self.under_test.validate_id_token_remote("test_token")
        self.assertEqual({}, results)

    def test_validate_id_token_local(self):
        results = self.under_test.validate_id_token_local("test_token")
        self.assertEqual({}, results)

    def test_validate_refresh_token(self):
        results = self.under_test.validate_refresh_token_remote("test_token")
        self.assertEqual({}, results)

    def test_revoke_access_token(self):
        # test passes if it doesn't raise an exception
        self.under_test.revoke_access_token("test_token")

    def test_revoke_refresh_token(self):
        # test passes if it doesn't raise an exception
        self.under_test.revoke_refresh_token("test_token")

    def test_get_scopes(self):
        results = self.under_test.get_scopes()
        self.assertEqual([], results)
