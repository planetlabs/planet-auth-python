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
from planet_auth.oidc.auth_clients.auth_code_flow import (
    AuthCodeAuthClient,
    AuthCodeClientConfig,
    AuthCodeWithClientSecretAuthClient,
    AuthCodeWithClientSecretClientConfig,
    AuthCodeWithPubKeyAuthClient,
    AuthCodeWithPubKeyClientConfig,
    AuthCodeAuthClientException,
)
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.request_authenticator import RefreshingOidcTokenRequestAuthenticator
from tests.test_planet_auth.util import tdata_resource_file_path
from tests.test_planet_auth.unit.auth.util import StubOidcClientConfig, StubOidcAuthClient

TEST_AUTH_SERVER = "https://blackhole.unittest.planet.com/fake_authserver"
TEST_CLIENT_ID = "fake_test_client_id"
TEST_CLIENT_SECRET = "fake_client_secret"
TEST_RECIRECT_URI_REMOTE = "https://blackhole.unittest.planet.com/auth_callback"
TEST_RECIRECT_URI_LOCAL = "http://localhost:8080/auth_callback"
TEST_TOKEN_SAVE_FILE_PATH = pathlib.Path("/test/token.json")
TEST_AUTH_CODE = "FAKE_TEST_AUTHCODE"
MOCK_TOKEN = {
    "token_type": "Bearer",
    "expires_in": 3600,
    "access_token": "__mock_access_token__",
    "scope": "offline_access openid profile planet",
    "refresh_token": "__mock_refresh_token__",
    "id_token": "__mock_id_token__",
}


class AuthCodeClientConfigTest(unittest.TestCase):
    def test_callback_urls_set(self):
        under_test = AuthCodeClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_RECIRECT_URI_REMOTE,
            local_redirect_uri=TEST_RECIRECT_URI_LOCAL,
        )
        under_test.check()
        self.assertEqual(TEST_RECIRECT_URI_REMOTE, under_test.redirect_uri())
        self.assertEqual(TEST_RECIRECT_URI_LOCAL, under_test.local_redirect_uri())

        under_test = AuthCodeClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_RECIRECT_URI_REMOTE,
            local_redirect_uri=None,
        )
        under_test.check()
        self.assertEqual(TEST_RECIRECT_URI_REMOTE, under_test.redirect_uri())
        self.assertEqual(TEST_RECIRECT_URI_REMOTE, under_test.local_redirect_uri())

        under_test = AuthCodeClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            redirect_uri=None,
            local_redirect_uri=TEST_RECIRECT_URI_LOCAL,
        )
        under_test.check()
        self.assertEqual(TEST_RECIRECT_URI_LOCAL, under_test.redirect_uri())
        self.assertEqual(TEST_RECIRECT_URI_LOCAL, under_test.local_redirect_uri())

        under_test = AuthCodeClientConfig(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, redirect_uri=None, local_redirect_uri=None
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


def mocked_authapi_get_authcode(
    obj_self, client_id, redirect_uri, requested_scopes, requested_audiences, pkce_code_challenge, extra
):
    return TEST_AUTH_CODE


def mocked_tokenapi_token_from_code(obj_self, redirect_uri, client_id, code, code_verifier, auth_enricher):
    return MOCK_TOKEN


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


class AuthCodeFlowTest(unittest.TestCase):
    def setUp(self):
        self.under_test = AuthCodeAuthClient(
            AuthCodeClientConfig(
                auth_server=TEST_AUTH_SERVER,
                token_endpoint=TEST_AUTH_SERVER + "/token",
                authorization_endpoint=TEST_AUTH_SERVER + "/auth",
                client_id=TEST_CLIENT_ID,
                redirect_uri=TEST_RECIRECT_URI_LOCAL,
            )
        )

    @mock.patch(
        "planet_auth.oidc.api_clients.authorization_api_client.AuthorizationApiClient.authcode_from_pkce_auth_request_with_browser_and_callback_listener",
        mocked_authapi_get_authcode,
    )
    @mock.patch(
        "planet_auth.oidc.api_clients.token_api_client.TokenApiClient.get_token_from_code",
        mocked_tokenapi_token_from_code,
    )
    def test_login_browser(self):
        test_result = self.under_test.login(allow_open_browser=True)
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        self.assertEqual(MOCK_TOKEN, test_result.data())

    @mock.patch(
        "planet_auth.oidc.api_clients.authorization_api_client.AuthorizationApiClient.authcode_from_pkce_auth_request_with_tty_input",
        mocked_authapi_get_authcode,
    )
    @mock.patch(
        "planet_auth.oidc.api_clients.token_api_client.TokenApiClient.get_token_from_code",
        mocked_tokenapi_token_from_code,
    )
    def test_login_no_browser(self):
        # override scopes to also test that code path in contrast to the
        # "with browser" case above.
        # No difference in the result between overriding the scopes or not
        # in this test. This is because the response is mocked.  A real auth
        # server might behave differently, but that's beyond the unit under
        # test here.  Same for audiences.
        test_result = self.under_test.login(
            allow_open_browser=False,
            allow_tty_prompt=True,
            requested_scopes=["override"],
            requested_audiences=["req_aud"],
        )
        self.assertIsInstance(test_result, FileBackedOidcCredential)
        self.assertEqual(MOCK_TOKEN, test_result.data())

    def test_login_fails_no_user_input_allowed(self):
        with self.assertRaises(AuthCodeAuthClientException):
            self.under_test.login(allow_open_browser=False, allow_tty_prompt=False)

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

    def test_auth_enricher(self):
        # The correctness of what enrichment does is determined by the OAuth
        # endpoint, and we've externalized the heavy lifting of preparing the
        # enrichment into helper functions that could be unit tested
        # separately. (So unit testing of that ought to be done there,
        # although perhaps testing it here in the context of a particular
        # flow here is more meaningful.)
        enriched_payload, auth = self.under_test._client_auth_enricher({}, "test_audience")

        # Payload enriched with *only* the client id.
        self.assertEqual({"client_id": TEST_CLIENT_ID}, enriched_payload)

        # No request auth expected
        self.assertIsNone(auth)


class AuthCodeWithClientSecretClientConfigTest(unittest.TestCase):
    def test_secret_required(self):
        # No exception
        under_test = AuthCodeWithClientSecretClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_RECIRECT_URI_REMOTE,
            client_secret=TEST_CLIENT_SECRET,
        )
        under_test.check()

        under_test = AuthCodeWithClientSecretClientConfig(
            auth_server=TEST_AUTH_SERVER, redirect_uri=TEST_RECIRECT_URI_REMOTE, client_id=TEST_CLIENT_ID
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class AuthCodeWithSecretFlowTest(unittest.TestCase):
    def setUp(self):
        self.under_test = AuthCodeWithClientSecretAuthClient(
            AuthCodeWithClientSecretClientConfig(
                auth_server=TEST_AUTH_SERVER,
                token_endpoint=TEST_AUTH_SERVER + "/token",
                authorization_endpoint=TEST_AUTH_SERVER + "/auth",
                client_id=TEST_CLIENT_ID,
                client_secret=TEST_CLIENT_SECRET,
                redirect_uri=TEST_RECIRECT_URI_LOCAL,
            )
        )

    def test_auth_enricher(self):
        # The correctness of what enrichment does is determined by the OAuth
        # endpoint, and we've externalized the heavy lifting of preparing the
        # enrichment into helper functions that could be unit tested
        # separately. (So unit testing of that ought to be done there,
        # although perhaps testing it here in the context of a particular
        # flow here is more meaningful.)
        enriched_payload, enriched_auth = self.under_test._client_auth_enricher({}, "test_audience")

        # When the HTTP Basic Auth enricher is used:
        ## No payload enrichment expected.
        self.assertEqual({}, enriched_payload)
        ## HTTP basic auth with the client secret.
        self.assertEqual(TEST_CLIENT_ID, enriched_auth.username)
        self.assertEqual(TEST_CLIENT_SECRET, enriched_auth.password)

        # When the payload secret enricher is used
        # self.assertEqual({"client_id": TEST_CLIENT_ID, "client_secret": TEST_CLIENT_SECRET}, enriched_payload)
        # self.assertIsNone(enriched_auth)


class AuthCodeWithPubKeyClientConfigTest(unittest.TestCase):
    def test_privkey_required(self):
        # No exception
        under_test = AuthCodeWithPubKeyClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_RECIRECT_URI_REMOTE,
            client_privkey_file="/dummy/utest/file",
        )
        under_test.check()

        # No exception
        under_test = AuthCodeWithPubKeyClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_RECIRECT_URI_REMOTE,
            client_privkey="dummy private key literal",
        )
        under_test.check()

        under_test = AuthCodeWithPubKeyClientConfig(
            auth_server=TEST_AUTH_SERVER, redirect_uri=TEST_RECIRECT_URI_REMOTE, client_id=TEST_CLIENT_ID
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class AuthCodeWithPubKeyFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.privkey_password = "password"
        cls.privkey_file_path = tdata_resource_file_path("keys/keypair1_priv.test_pem")

    def setUp(self):
        self.under_test = AuthCodeWithPubKeyAuthClient(
            AuthCodeWithPubKeyClientConfig(
                auth_server=TEST_AUTH_SERVER,
                token_endpoint=TEST_AUTH_SERVER + "/token",
                authorization_endpoint=TEST_AUTH_SERVER + "/auth",
                client_id=TEST_CLIENT_ID,
                client_privkey_password=self.privkey_password,
                client_privkey_file=self.privkey_file_path,
                redirect_uri=TEST_RECIRECT_URI_LOCAL,
            )
        )

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
