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

from planet_auth.auth import Auth
from planet_auth.auth_client import AuthClientException, AuthClientConfig
from planet_auth.static_api_key.auth_client import StaticApiKeyAuthClient
from planet_auth.static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator
from planet_auth.none.noop_auth import NoOpAuthClient

from tests.test_planet_auth.util import tdata_resource_file_path


class AuthTest(unittest.TestCase):
    def test_initialize_from_conffile_with_no_token_file(self):
        under_test = Auth.initialize_from_config(
            client_config=AuthClientConfig.from_file(
                tdata_resource_file_path("auth_client_configs/utest/static_api_key.json")
            ),
        )
        self.assertIsInstance(under_test.auth_client(), StaticApiKeyAuthClient)
        self.assertIsInstance(under_test.request_authenticator(), FileBackedApiKeyRequestAuthenticator)
        self.assertIsNone(under_test.token_file_path())
        self.assertIsNone(under_test.profile_name())

    def test_initialize_from_conffile_with_token_file(self):
        under_test = Auth.initialize_from_config(
            client_config=AuthClientConfig.from_file(
                tdata_resource_file_path("auth_client_configs/utest/static_api_key.json")
            ),
            token_file="/dev/null/test_token.json",
        )
        self.assertIsInstance(under_test.auth_client(), StaticApiKeyAuthClient)
        self.assertIsInstance(under_test.request_authenticator(), FileBackedApiKeyRequestAuthenticator)
        self.assertIsInstance(under_test.token_file_path(), pathlib.Path)
        self.assertEqual(pathlib.Path("/dev/null/test_token.json"), under_test.token_file_path())
        self.assertIsNone(under_test.profile_name())

    def test_initialize_from_config(self):
        under_test = Auth.initialize_from_config_dict(
            client_config={"client_type": "none"}, token_file="/dev/null/token.json"
        )
        self.assertIsInstance(under_test.auth_client(), NoOpAuthClient)
        self.assertEqual(under_test.token_file_path(), pathlib.Path("/dev/null/token.json"))
        self.assertIsNone(under_test.profile_name())

    def test_initialize_from_config_invalid_client(self):
        with self.assertRaises(AuthClientException):
            Auth.initialize_from_config_dict(
                client_config={"client_type": "invalid"}, token_file="/dev/null/token.json"
            )

    def test_initialize_from_config_none_client(self):
        with self.assertRaises(AuthClientException):
            Auth.initialize_from_config_dict(client_config=None, token_file="/dev/null/token.json")
