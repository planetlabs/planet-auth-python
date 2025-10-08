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

import freezegun
import pathlib
import tempfile
import time
import unittest

from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.storage_utils import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


class TestOidcCredential(unittest.TestCase):
    def test_asserts_valid(self):
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_opaque_tokens_with_lifespan_non_augmented.json"
            ),
        )
        under_test.load()
        self.assertIsNotNone(under_test.data())

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data(None)

        with self.assertRaises(FileBackedJsonObjectException):
            under_test.set_data({"test": "missing all required fields"})

    def test_getters(self):
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_opaque_tokens_with_lifespan_non_augmented.json"
            ),
        )
        under_test.load()
        self.assertEqual("_dummy_access_token_", under_test.access_token())
        self.assertEqual("_dummy_refresh_token_", under_test.refresh_token())
        self.assertEqual("_dummy_id_token_", under_test.id_token())

    def test_load_credential_file__jwt_tokens__augmented__with_lifespan(self):
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_jwt_tokens_with_lifespan_augmented.json"
            ),
        )
        self.assertEqual(1759206891, under_test.issued_time())
        self.assertEqual(1759206951, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    def test_load_credential_file__jwt_tokens__non_augmented__with_lifespan(self):
        # Older versions of the code may have saved files without our computed fields.
        # Check that this behaves as expected.
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_jwt_tokens_with_lifespan_non_augmented.json"
            ),
        )
        self.assertEqual(1759206891, under_test.issued_time())
        self.assertEqual(1759206951, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    def test_load_credential_file__jwt_tokens__augmented__without_lifespan(self):
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_jwt_tokens_no_lifespan_augmented.json"
            ),
        )
        self.assertEqual(1759206891, under_test.issued_time())
        self.assertEqual(1759206951, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    def test_load_credential_file__jwt_tokens__non_augmented__without_lifespan(self):
        # Older versions of the code may have saved files without our computed fields.
        # Check that this behaves as expected.
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_jwt_tokens_no_lifespan_non_augmented.json"
            ),
        )
        self.assertEqual(1759206891, under_test.issued_time())
        self.assertEqual(1759206951, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    def test_load_credential_file__opaque_tokens__augmented__with_lifespan(self):
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_opaque_tokens_with_lifespan_augmented.json"
            ),
        )
        self.assertEqual(1, under_test.issued_time())
        self.assertEqual(101, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_load_credential_file__opaque_tokens__non_augmented__with_lifespan(self, frozen_time):
        # Older versions of the code may have saved files without our computed fields.
        # Check that this behaves as expected.
        t0 = int(time.time())
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_opaque_tokens_with_lifespan_non_augmented.json"
            ),
        )
        self.assertEqual(t0, under_test.issued_time())
        self.assertEqual(t0 + 3600, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    def test_load_credential_file__opaque_tokens__augmented__without_lifespan(self):
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_opaque_tokens_no_lifespan_augmented.json"
            ),
        )
        self.assertEqual(1, under_test.issued_time())
        self.assertEqual(101, under_test.expiry_time())
        self.assertTrue(under_test.is_expiring())
        self.assertFalse(under_test.is_non_expiring())

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_load_credential_file__opaque_tokens__non_augmented__without_lifespan(self, frozen_time):
        # Older versions of the code may have saved files without our computed fields.
        # Check that this behaves as expected.
        t0 = int(time.time())
        under_test = FileBackedOidcCredential(
            data=None,
            credential_file=tdata_resource_file_path(
                "keys/oidc_test_credential_opaque_tokens_no_lifespan_non_augmented.json"
            ),
        )
        self.assertEqual(t0, under_test.issued_time())
        self.assertIsNone(under_test.expiry_time())
        self.assertFalse(under_test.is_expiring())
        self.assertTrue(under_test.is_non_expiring())


class TestBaseCredential(unittest.TestCase):
    # Test the Credential base class functions using the OidcCredential derived class.
    # The primary base class functionality under test is the IAT and EXP times
    # and their persistence behavior.

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_save_persists_computed_values_with_lifespan(self, frozen_time):
        tmp_dir = tempfile.TemporaryDirectory()
        test_path = pathlib.Path(tmp_dir.name) / "test_save_computed_data.json"
        t0 = int(time.time())
        under_test_1 = FileBackedOidcCredential(
            data={
                "expires_in": 1000,
                "token_type": "Bearer",
                "scope": "offline_access profile openid",
                "access_token": "_dummy_access_token_",
                "refresh_token": "_dummy_refresh_token_",
                "id_token": "_dummy_id_token_",
            }
        )
        self.assertEqual(t0, under_test_1.issued_time())
        self.assertEqual(t0 + 1000, under_test_1.expiry_time())
        self.assertTrue(under_test_1.is_expiring())
        self.assertFalse(under_test_1.is_non_expiring())
        self.assertFalse(under_test_1.is_expired())
        self.assertTrue(under_test_1.is_not_expired())
        under_test_1.set_path(test_path)
        under_test_1.save()

        frozen_time.tick(100)

        under_test_2 = FileBackedOidcCredential(data=None, credential_file=test_path)
        self.assertEqual(t0, under_test_2.issued_time())
        self.assertEqual(t0 + 1000, under_test_2.expiry_time())
        self.assertTrue(under_test_2.is_expiring())
        self.assertFalse(under_test_2.is_non_expiring())
        self.assertFalse(under_test_2.is_expired())
        self.assertTrue(under_test_2.is_not_expired())

        frozen_time.tick(1000)

        self.assertTrue(under_test_2.is_expired())
        self.assertFalse(under_test_2.is_not_expired())

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_save_persists_computed_values_without_lifespan(self, frozen_time):
        tmp_dir = tempfile.TemporaryDirectory()
        test_path = pathlib.Path(tmp_dir.name) / "test_save_computed_data.json"
        t0 = int(time.time())
        under_test_1 = FileBackedOidcCredential(
            data={
                "token_type": "Bearer",
                "scope": "offline_access profile openid",
                "access_token": "_dummy_access_token_",
                "refresh_token": "_dummy_refresh_token_",
                "id_token": "_dummy_id_token_",
            }
        )
        self.assertEqual(t0, under_test_1.issued_time())
        self.assertIsNone(under_test_1.expiry_time())
        self.assertFalse(under_test_1.is_expiring())
        self.assertTrue(under_test_1.is_non_expiring())
        self.assertFalse(under_test_1.is_expired())
        self.assertTrue(under_test_1.is_not_expired())
        under_test_1.set_path(test_path)
        under_test_1.save()

        frozen_time.tick(100)

        under_test_2 = FileBackedOidcCredential(data=None, credential_file=test_path)
        self.assertEqual(t0, under_test_2.issued_time())
        self.assertIsNone(under_test_2.expiry_time())
        self.assertFalse(under_test_2.is_expiring())
        self.assertTrue(under_test_2.is_non_expiring())
        self.assertFalse(under_test_2.is_expired())
        self.assertTrue(under_test_2.is_not_expired())

        frozen_time.tick(1000)

        self.assertFalse(under_test_2.is_expired())
        self.assertTrue(under_test_2.is_not_expired())
