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

from planet_auth import FileBackedOidcCredential
from planet_auth.static_api_key.auth_client import (
    StaticApiKeyAuthClient,
    StaticApiKeyAuthClientConfig,
    StaticApiKeyAuthClientException,
)
from planet_auth.static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator
from planet_auth.static_api_key.static_api_key import FileBackedApiKey
from tests.test_planet_auth.util import tdata_resource_file_path


class TestStaticApiKeyAuthClient(unittest.TestCase):
    def setUp(self) -> None:
        self.client_conf_file = tdata_resource_file_path("auth_client_configs/utest/static_api_key_with_key.json")

    def test_login_missing_api_key(self):
        under_test = StaticApiKeyAuthClient(StaticApiKeyAuthClientConfig(api_key=None))
        with self.assertRaises(StaticApiKeyAuthClientException):
            under_test.login()

    def test_login_with_api_key(self):
        under_test = StaticApiKeyAuthClient(StaticApiKeyAuthClientConfig(api_key="test_api_key"))
        under_test_credential = under_test.login()
        self.assertIsInstance(under_test_credential, FileBackedApiKey)

    def test_default_request_authenticator_type(self):
        under_test = StaticApiKeyAuthClient(StaticApiKeyAuthClientConfig())
        test_result = under_test.default_request_authenticator(credential=pathlib.Path("/test/token.json"))
        #  test_result = under_test_no_apikey_in_conf_in_memory.default_request_authenticator(credential=None)
        self.assertIsInstance(test_result, FileBackedApiKeyRequestAuthenticator)
        self.assertEqual(pathlib.Path("/test/token.json"), test_result._credential.path())

    def test_default_request_authenticator_apikey_in_config_file(self):
        under_test_config = StaticApiKeyAuthClientConfig(file_path=self.client_conf_file)
        under_test = StaticApiKeyAuthClient(under_test_config)
        test_result = under_test.default_request_authenticator(credential=pathlib.Path("/test/token.json"))

        self.assertIsInstance(test_result, FileBackedApiKeyRequestAuthenticator)
        test_result.pre_request_hook()
        self.assertEqual("utest_static_api_key_in_file", test_result._token_body)
        self.assertEqual(self.client_conf_file, test_result._credential.path())

    def test_default_request_authenticator_apikey_in_memory_config(self):
        under_test_config = StaticApiKeyAuthClientConfig(api_key="constructor_api_key")
        under_test = StaticApiKeyAuthClient(under_test_config)
        test_result = under_test.default_request_authenticator(credential=pathlib.Path("/test/token.json"))

        self.assertIsInstance(test_result, FileBackedApiKeyRequestAuthenticator)
        test_result.pre_request_hook()
        self.assertEqual("constructor_api_key", test_result._token_body)
        self.assertIsNone(test_result._credential.path())

    def test_default_request_authenticator_given_literal_credential_object_instead_of_path(self):
        under_test_config = StaticApiKeyAuthClientConfig()
        under_test = StaticApiKeyAuthClient(under_test_config)
        literal_credential = FileBackedApiKey(api_key="literal_utest_api_credential")
        test_result = under_test.default_request_authenticator(credential=literal_credential)
        test_result.pre_request_hook()
        self.assertEqual("literal_utest_api_credential", test_result._token_body)

    def test_default_request_authenticator_given_invalid_type(self):
        under_test = StaticApiKeyAuthClient(StaticApiKeyAuthClientConfig())
        literal_credential = FileBackedOidcCredential()
        with self.assertRaises(TypeError):
            under_test.default_request_authenticator(credential=literal_credential)
