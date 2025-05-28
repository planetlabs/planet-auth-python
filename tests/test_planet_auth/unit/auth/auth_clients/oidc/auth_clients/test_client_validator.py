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

from planet_auth.auth_client import AuthClientException
from planet_auth.none.noop_auth import NoOpCredential
from planet_auth.oidc.auth_clients.client_validator import (
    OidcClientValidatorAuthClientConfig,
    OidcClientValidatorAuthClient,
)
from planet_auth.request_authenticator import ForbiddenRequestAuthenticator


TEST_AUTH_SERVER_BASE = "https://auth.unittest.planet.com"


class ClientValidatorAuthClientConfigTest(unittest.TestCase):
    def test_default_client_id(self):
        under_test = OidcClientValidatorAuthClientConfig(auth_server=TEST_AUTH_SERVER_BASE)
        self.assertEqual(OidcClientValidatorAuthClientConfig.INTERNAL_CLIENT_ID, under_test.client_id())
        under_test = OidcClientValidatorAuthClientConfig(
            client_id="_utest_client_id_", auth_server=TEST_AUTH_SERVER_BASE
        )
        self.assertEqual("_utest_client_id_", under_test.client_id())


class ClientValidatorAuthClientTest(unittest.TestCase):
    # Most of the ClientValidatorAuthClientTest is actually base class functionality,
    # and unit tested with the base class.
    def setUp(self):
        self.under_test = OidcClientValidatorAuthClient(
            OidcClientValidatorAuthClientConfig(auth_server=TEST_AUTH_SERVER_BASE)
        )

    def test_login_fails(self):
        with self.assertRaises(AuthClientException):
            self.under_test.login()

    def test_refresh_fails(self):
        with self.assertRaises(AuthClientException):
            self.under_test.refresh(refresh_token="utest_dummy_refresh_token")

    def test_default_request_authenticator_type(self):
        test_result = self.under_test.default_request_authenticator(credential=NoOpCredential())
        self.assertIsInstance(test_result, ForbiddenRequestAuthenticator)
