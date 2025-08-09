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
from unittest import mock

from planet_auth import FileBackedOidcCredential, RefreshingOidcTokenRequestAuthenticator, FileBackedApiKey
from planet_auth.oidc.auth_clients.device_code_flow import (
    DeviceCodeClientConfig,
    DeviceCodeAuthClient,
    DeviceCodeAuthClientException,
)
from tests.test_planet_auth.unit.auth.util import StubOidcClientConfig, StubOidcAuthClient
from tests.test_planet_auth.util import tdata_resource_file_path, mock_sleep_skip

TEST_AUTH_SERVER = "https://blackhole.unittest.planet.com/fake_authserver"
TEST_CLIENT_ID = "fake_test_client_id"
TEST_TOKEN_SAVE_FILE_PATH = pathlib.Path("/test/token.json")
MOCK_TOKEN = {"token_type": "Bearer", "expires_in": 3600, "access_token": "__mock_access_token__", "scope": "planet"}
MOCK_DEVICE_AUTH_REQ_RESULT_WITH_COMPLETE_URI = {
    "device_code": "__mock_device_code__",
    "user_code": "__mock_user_code__",
    "verification_uri": "__mock_verification_uri__",
    "verification_uri_complete": "__mock_verification_uri_complete__",
    "expires_in": 100,
    "interval": 1,
}
MOCK_DEVICE_AUTH_REQ_RESULT_WITHOUT_COMPLETE_URI = {
    "device_code": "__mock_device_code__",
    "user_code": "__mock_user_code__",
    "verification_uri": "__mock_verification_uri__",
    "expires_in": 100,
    "interval": 1,
}

# Get some tokens that look more real than the mock token for some tests.
TEST_SIGNING_KEY_FILE = tdata_resource_file_path("keys/keypair1_priv_nopassword.test_pem")
TEST_SIGNING_PUBKEY_FILE = tdata_resource_file_path("keys/keypair1_pub_jwk.json")
STUB_AUTH_CLIENT_CONFIG = StubOidcClientConfig(
    auth_server=TEST_AUTH_SERVER,
    stub_authority_ttl=3600,
    stub_authority_access_token_audience="utest_audience",
    stub_authority_signing_key_file=TEST_SIGNING_KEY_FILE,
    stub_authority_pub_key_file=TEST_SIGNING_PUBKEY_FILE,
    scopes=["offline_access", "profile", "openid", "test_scope_1", "test_scope_2"],
)
STUB_AUTH_CLIENT = StubOidcAuthClient(STUB_AUTH_CLIENT_CONFIG)


def mocked_devauthapi_request_code_with_complete_uri(
    obj_self, client_id, requested_scopes, requested_audiences, auth_enricher, extra
):
    return MOCK_DEVICE_AUTH_REQ_RESULT_WITH_COMPLETE_URI


def mocked_devauthapi_request_code_without_complete_uri(
    obj_self, client_id, requested_scopes, requested_audiences, auth_enricher, extra
):
    return MOCK_DEVICE_AUTH_REQ_RESULT_WITHOUT_COMPLETE_URI


def mocked_tokenapi_from_device_code(obj_self, client_id, device_code, timeout, poll_interval, auth_enricher):
    return MOCK_TOKEN


class DeviceCodeNoClientAuthTest(unittest.TestCase):
    def setUp(self):
        self.under_test = DeviceCodeAuthClient(
            DeviceCodeClientConfig(
                auth_server=TEST_AUTH_SERVER,
                client_id=TEST_CLIENT_ID,
                token_endpoint=TEST_AUTH_SERVER + "/token",
                device_authorization_endpoint=TEST_AUTH_SERVER + "/device_auth",
            )
        )

    @mock.patch("time.sleep", mock_sleep_skip)
    @mock.patch(
        "planet_auth.oidc.api_clients.token_api_client.TokenApiClient.poll_for_token_from_device_code",
        mocked_tokenapi_from_device_code,
    )
    @mock.patch(
        "planet_auth.oidc.api_clients.device_authorization_api_client.DeviceAuthorizationApiClient.request_device_code",
        mocked_devauthapi_request_code_with_complete_uri,
    )
    def test_login_1(self):
        test_result = self.under_test.login(allow_tty_prompt=True)
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        self.assertEqual(MOCK_TOKEN, test_result.data())

        # again with override scopes, but since the response is mocked
        # there is nothing different to check in the result data.
        # Same goes for audiences.
        test_result = self.under_test.login(
            allow_tty_prompt=True, requested_scopes=["override1"], requested_audiences=["req_aud1"]
        )
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        # self.assertEqual(MOCK_TOKEN, test_result.data())

    @mock.patch("time.sleep", mock_sleep_skip)
    @mock.patch(
        "planet_auth.oidc.api_clients.token_api_client.TokenApiClient.poll_for_token_from_device_code",
        mocked_tokenapi_from_device_code,
    )
    @mock.patch(
        "planet_auth.oidc.api_clients.device_authorization_api_client.DeviceAuthorizationApiClient.request_device_code",
        mocked_devauthapi_request_code_without_complete_uri,
    )
    def test_login_2(self):
        # As above, but a slightly different response
        test_result = self.under_test.login(allow_tty_prompt=True)
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        self.assertEqual(MOCK_TOKEN, test_result.data())

    def test_default_request_authenticator_type(self):
        test_result = self.under_test.default_request_authenticator(credential=TEST_TOKEN_SAVE_FILE_PATH)
        self.assertIsInstance(test_result, RefreshingOidcTokenRequestAuthenticator)

    def test_default_request_authenticator_given_literal_credential_object_instead_of_path(self):
        literal_credential = STUB_AUTH_CLIENT.login()
        test_result = self.under_test.default_request_authenticator(credential=literal_credential)
        test_result.pre_request_hook()
        self.assertEqual(literal_credential.access_token(), test_result._token_body)

    def test_default_request_authenticator_given_invalid_type(self):
        literal_credential = FileBackedApiKey()
        with self.assertRaises(TypeError):
            self.under_test.default_request_authenticator(credential=literal_credential)

    def test_login_fails_no_user_input_allowed(self):
        with self.assertRaises(DeviceCodeAuthClientException):
            self.under_test.login(allow_open_browser=False, allow_tty_prompt=False)


class DeviceCodeClientSecretClientAuthTest(unittest.TestCase):
    # No substance to test in this class
    pass


class DeviceCodeClientPubKeyClientAuthTest(unittest.TestCase):
    # No substance to test in this class
    pass
