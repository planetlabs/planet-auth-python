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

from planet_auth import FileBackedApiKey
from planet_auth.auth_client import AuthClientConfigException
from planet_auth.oidc.auth_clients.client_credentials_flow import (
    ClientCredentialsPubKeyAuthClient,
    ClientCredentialsPubKeyClientConfig,
    ClientCredentialsClientSecretAuthClient,
    ClientCredentialsClientSecretClientConfig,
)
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.request_authenticator import RefreshOrReloginOidcTokenRequestAuthenticator
from tests.test_planet_auth.unit.auth.util import StubOidcClientConfig, StubOidcAuthClient
from tests.test_planet_auth.util import tdata_resource_file_path

TEST_AUTH_SERVER = "https://blackhole.unittest.planet.com/fake_authserver"
TEST_CLIENT_ID = "fake_test_client_id"
TEST_CLIENT_SECRET = "fake_test_client_secret"
TEST_TOKEN_SAVE_FILE_PATH = pathlib.Path("/test/token.json")
MOCK_TOKEN = {"token_type": "Bearer", "expires_in": 3600, "access_token": "__mock_access_token__", "scope": "planet"}

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


def mocked_tokenapi_ccred(obj_self, client_id, requested_scopes, requested_audiences, auth_enricher, extra):
    return MOCK_TOKEN


class ClientCredentialsClientSecretConfigTest(unittest.TestCase):
    def test_secret_required(self):
        # No exception
        under_test = ClientCredentialsClientSecretClientConfig(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_secret=TEST_CLIENT_SECRET
        )
        under_test.check()

        under_test = ClientCredentialsClientSecretClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID)
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class ClientCredentialsClientSecretFlowTest(unittest.TestCase):
    def setUp(self):
        self.under_test = ClientCredentialsClientSecretAuthClient(
            ClientCredentialsClientSecretClientConfig(
                auth_server=TEST_AUTH_SERVER,
                token_endpoint=TEST_AUTH_SERVER + "/token",
                client_id=TEST_CLIENT_ID,
                client_secret=TEST_CLIENT_SECRET,
            )
        )

    @mock.patch(
        "planet_auth.oidc.api_clients.token_api_client.TokenApiClient.get_token_from_client_credentials",
        mocked_tokenapi_ccred,
    )
    def test_login(self):
        test_result = self.under_test.login()
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        self.assertEqual(MOCK_TOKEN, test_result.data())

        # again with override scopes, but since the response is mocked
        # there is nothing different to check in the result data.
        # Same goes for audiences.
        test_result = self.under_test.login(requested_scopes=["override1"], requested_audiences=["req_aud1"])
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        # self.assertEqual(MOCK_TOKEN, test_result.data())

    def test_default_request_authenticator_type(self):
        test_result = self.under_test.default_request_authenticator(credential=TEST_TOKEN_SAVE_FILE_PATH)
        self.assertIsInstance(test_result, RefreshOrReloginOidcTokenRequestAuthenticator)

    def test_auth_enricher(self):
        # The correctness of what enrichment does is determined by the OAuth
        # endpoint, and we've externalized the heavy lifting of preparing the
        # enrichment into helper functions that could be unit tested
        # separately. (So unit testing of that ought to be done there,
        # although perhaps testing it here in the context of a particular
        # flow here is more meaningful.)
        enriched_payload, auth = self.under_test._client_auth_enricher({}, "test_audience")

        # No payload enrichment expected.
        self.assertEqual({}, enriched_payload)

        # HTTP basic auth with the client secret.
        self.assertEqual(TEST_CLIENT_ID, auth.username)
        self.assertEqual(TEST_CLIENT_SECRET, auth.password)

    def test_auth_login_enricher(self):
        # Client secret client credentials uses a different enricher
        # for logins vs more other use cases.  Again, it's not called
        # by the class directly, but by an API client that is mocked out
        # for unit tests. Again, the arbiter of what is correct is
        # the external token server.
        enriched_payload, enriched_auth = self.under_test._client_auth_enricher_login({}, "test_audience")

        # Client secret ought to be put into the payload
        self.assertEqual({"client_id": TEST_CLIENT_ID, "client_secret": TEST_CLIENT_SECRET}, enriched_payload)
        self.assertIsNone(enriched_auth)


class ClientCredentialsPubKeyClientConfigTest(unittest.TestCase):
    def test_privkey_required(self):
        # No exception
        under_test = ClientCredentialsPubKeyClientConfig(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_privkey_file="/dummy/utest/file"
        )
        under_test.check()

        # No exception
        under_test = ClientCredentialsPubKeyClientConfig(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_privkey="dummy private key literal"
        )
        under_test.check()

        under_test = ClientCredentialsPubKeyClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID)
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class ClientCredentialsPubKeyFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.privkey_password = "password"
        cls.privkey_file_path = tdata_resource_file_path("keys/keypair1_priv.test_pem")

    def setUp(self):
        self.under_test = ClientCredentialsPubKeyAuthClient(
            ClientCredentialsPubKeyClientConfig(
                auth_server=TEST_AUTH_SERVER,
                token_endpoint=TEST_AUTH_SERVER + "/token",
                client_id=TEST_CLIENT_ID,
                client_privkey_password=self.privkey_password,
                client_privkey_file=self.privkey_file_path,
            )
        )

    @mock.patch(
        "planet_auth.oidc.api_clients.token_api_client.TokenApiClient.get_token_from_client_credentials",
        mocked_tokenapi_ccred,
    )
    def test_login(self):
        test_result = self.under_test.login()
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        self.assertEqual(MOCK_TOKEN, test_result.data())

        # again with override scopes, but since the response is mocked
        # there is nothing different to check in the result data/
        # Same goes for audiences.
        test_result = self.under_test.login(requested_scopes=["override1"], requested_audiences=["req_aud1"])
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        # self.assertEqual(MOCK_TOKEN, test_result.data())

    def test_default_request_authenticator_type(self):
        test_result = self.under_test.default_request_authenticator(credential=TEST_TOKEN_SAVE_FILE_PATH)
        self.assertIsInstance(test_result, RefreshOrReloginOidcTokenRequestAuthenticator)

    def test_default_request_authenticator_given_literal_credential_object_instead_of_path(self):
        literal_credential = STUB_AUTH_CLIENT.login()
        test_result = self.under_test.default_request_authenticator(credential=literal_credential)
        test_result.pre_request_hook()
        self.assertEqual(literal_credential.access_token(), test_result._token_body)

    def test_default_request_authenticator_given_invalid_type(self):
        literal_credential = FileBackedApiKey()
        with self.assertRaises(TypeError):
            self.under_test.default_request_authenticator(credential=literal_credential)

    def test_auth_enricher(self):
        # The correctness of what enrichment does is determined by the OAuth
        # endpoint, and we've externalized the heavy lifting of preparing the
        # enrichment into helper functions that could be unit tested
        # separately. (So unit testing of that ought to be done there,
        # although perhaps testing it here in the context of a particular
        # flow here is more meaningful.)
        enriched_payload, auth = self.under_test._client_auth_enricher({}, "test_audience")

        # Payload enriched with a signed key assertion
        self.assertEqual(
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", enriched_payload.get("client_assertion_type")
        )
        self.assertIsNotNone(enriched_payload.get("client_assertion"))

        # No request auth expected
        self.assertIsNone(auth)
