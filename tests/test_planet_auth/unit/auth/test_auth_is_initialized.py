# Copyright 2025 Planet Labs PBC.
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

import json
import unittest
import pytest

from abc import ABC
from unittest import mock
from requests import Response

from planet_auth.constants import TOKEN_FILE_PLAIN, AUTH_CONFIG_FILE_PLAIN
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.profile import Profile

from tests.test_planet_auth.unit.auth.util import MockObjectStorageProvider, TestTokenBuilder


# This isn't the best unit test of Auth.  Rather, this tests how several
# things come together to make the request_authenticator_is_ready() work as
# expected in the Auth class.  We run this test for a number of common
# auth clients and authenticators.  This probably points to a code smell
# that this part of the library isn't that cleanly encapsulated.
# It's worth investigating if the Auth class should be some form of GSSAPI
# binding.

TEST_AUTH_SERVER = "https://login-utest.planet.com/"
TEST_AUDIENCE = "https://utest.planet.com/"


_pubkey, _mock_token_builder = TestTokenBuilder.test_token_builder_factory(keypair_name="keypair1")


def mocked_get_password(**kwargs):
    return "_mock_authcode_"


def _mock_oidc_credential_data() -> dict:
    # Data that is the same as what we expect in FileBackedOidcCredential.data
    return {
        "access_token": _mock_token_builder.construct_oidc_access_token_rfc8693(
            username="utest_user", requested_scopes=["planet", "offline_access"], ttl=100
        ),
        "refresh_token": "__FAKE_UTEST_REFRESH_TOKEN__",
        "expires_in": 100,
    }


def mock_oauth_http_svc(request_url, **kwargs):
    mock_http_data = {
        f"{TEST_AUTH_SERVER}.well-known/openid-configuration": {
            "issuer": f"{TEST_AUTH_SERVER}",
            "authorization_endpoint": f"{TEST_AUTH_SERVER}oauth/authorize",
            "token_endpoint": f"{TEST_AUTH_SERVER}oauth/token",
            "device_authorization_endpoint": f"{TEST_AUTH_SERVER}oauth/device/code",
        },
        f"{TEST_AUTH_SERVER}oauth/device/code": {
            "device_code": "mock_device_code",
            "user_code": "mock_user_code",
            "verification_uri": f"{TEST_AUTH_SERVER}verify",
            "expires_in": 100,
        },
        f"{TEST_AUTH_SERVER}oauth/authorize": {},
        f"{TEST_AUTH_SERVER}oauth/token": _mock_oidc_credential_data(),
    }
    response = Response()
    response.headers["content-type"] = "application/json"
    if request_url in mock_http_data:
        response.status_code = 200
        response._content = str.encode(json.dumps(mock_http_data[request_url]))
    else:
        response.status_code = 404

    return response


class IsInitializedTestBaseForOAuth2Client(ABC):
    def _profilePath(self, profile_name, file_name):
        return Profile.get_profile_file_path(profile=profile_name, filename=file_name)

    def _initMockStorage(self):
        self.test_client_data_in_storage = {
            "storage-utest-m2m-with-credential": {
                "client-config": {
                    "client_type": "oidc_client_credentials_secret",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_1__",
                    "client_secret": "__UTEST_CLIENT_SECRET__",
                },
                "saved-token": _mock_oidc_credential_data(),
            },
            "storage-utest-m2m-without-credential": {
                "client-config": {
                    "client_type": "oidc_client_credentials_secret",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_2__",
                    "client_secret": "__UTEST_CLIENT_SECRET__",
                },
            },
            "storage-utest-device-code-with-credential": {
                "client-config": {
                    "client_type": "oidc_device_code",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_3__",
                    "scopes": [
                        "planet",
                        "offline_access",
                    ],
                },
                "saved-token": _mock_oidc_credential_data(),
            },
            "storage-utest-device-code-without-credential": {
                "client-config": {
                    "client_type": "oidc_device_code",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_4__",
                    "scopes": [
                        "planet",
                        "offline_access",
                    ],
                },
            },
            "storage-utest-auth-code-with-credential": {
                "client-config": {
                    "client_type": "oidc_auth_code",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_5__",
                    "redirect_uri": "http://localhost:8080/",
                    "scopes": [
                        "planet",
                        "offline_access",
                    ],
                },
                "saved-token": _mock_oidc_credential_data(),
            },
            "storage-utest-auth-code-without-credential": {
                "client-config": {
                    "client_type": "oidc_auth_code",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_6__",
                    "redirect_uri": "http://localhost:8080/",
                    "scopes": [
                        "planet",
                        "offline_access",
                    ],
                },
            },
        }

        self.test_client_data_in_memory = {
            "mem-utest-m2m-without-credential": {
                "client-config": {
                    "client_type": "oidc_client_credentials_secret",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_102__",
                    "client_secret": "__UTEST_CLIENT_SECRET__",
                },
            },
            "mem-utest-device-code-without-credential": {
                "client-config": {
                    "client_type": "oidc_device_code",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_104__",
                    "scopes": [
                        "planet",
                        "offline_access",
                    ],
                },
            },
            "mem-utest-auth-code-without-credential": {
                "client-config": {
                    "client_type": "oidc_auth_code",
                    "auth_server": f"{TEST_AUTH_SERVER}",
                    "audiences": [f"{TEST_AUDIENCE}"],
                    "client_id": "__UTEST_CLIENT_ID_106__",
                    "redirect_uri": "http://localhost:8080/",
                    "scopes": [
                        "planet",
                        "offline_access",
                    ],
                },
            },
        }

        initial_mock_storage_initial_state = {}
        for profile_name in self.test_client_data_in_storage:
            client_data = self.test_client_data_in_storage[profile_name]
            client_conf_path = self._profilePath(profile_name=profile_name, file_name=AUTH_CONFIG_FILE_PLAIN)
            token_path = self._profilePath(profile_name=profile_name, file_name=TOKEN_FILE_PLAIN)
            if "client-config" in client_data:
                initial_mock_storage_initial_state[client_conf_path] = client_data["client-config"]
            if "saved-token" in client_data:
                initial_mock_storage_initial_state[token_path] = client_data["saved-token"]

        self.mock_storage_provider = MockObjectStorageProvider(initial_mock_storage=initial_mock_storage_initial_state)

    def setUp(self):
        self._initMockStorage()


class TestAuthIsInitialized_authCodeAuthClient(unittest.TestCase, IsInitializedTestBaseForOAuth2Client):
    def setUp(self):
        super()._initMockStorage()

    def test_session_is_initialized__in_memory__without_initial_credential_data(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-auth-code-without-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="some-random-utest-name",
            save_profile_config=False,
            save_token_file=False,
        )
        self.assertFalse(under_test.request_authenticator_is_ready())

    def test_session_is_initialized_by_existing_credential__in_memory__with_initial_credential_data(self):
        # Not expected to be a common case.  If you have a saved credential, you should be using storage.
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-auth-code-without-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="some-random-utest-name",
            save_profile_config=False,
            save_token_file=False,
            initial_token_data=_mock_oidc_credential_data(),
        )
        self.assertTrue(under_test.request_authenticator_is_ready())

    def test_session_is_initialized_by_existing_credential__with_storage__with_stored_credential_data(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_storage["storage-utest-auth-code-with-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="storage-utest-auth-code-with-credential",
            save_profile_config=True,
            save_token_file=True,
            initial_token_data=None,
        )
        self.assertTrue(under_test.request_authenticator_is_ready())

    @mock.patch("requests.sessions.Session.post", side_effect=mock_oauth_http_svc)
    @mock.patch("requests.sessions.Session.get", side_effect=mock_oauth_http_svc)
    @mock.patch("getpass.getpass", mocked_get_password)
    def test_session_is_initialized_by_login__in_memory__login_causes_session_to_be_initialized(
        self, mock_http_get, mock_http_post
    ):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-auth-code-without-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="some-random-utest-name",
            save_profile_config=False,
            save_token_file=False,
        )
        self.assertFalse(under_test.request_authenticator_is_ready())
        under_test.login(allow_tty_prompt=True, allow_open_browser=False)
        self.assertTrue(under_test.request_authenticator_is_ready())

    @pytest.mark.xfail(reason="TODO: Custom storage providers used by this test not yet supported for client profiles")
    @mock.patch("requests.sessions.Session.post", side_effect=mock_oauth_http_svc)
    @mock.patch("requests.sessions.Session.get", side_effect=mock_oauth_http_svc)
    def test_session_is_initialized_by_login__with_storage__profile_from_storage(self, mock_http_get, mock_http_post):
        under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt="storage-utest-auth-code-without-credential",
            save_profile_config=True,
            save_token_file=True,
            # storage_provider=self.mock_storage_provider,
        )
        self.assertFalse(under_test.request_authenticator_is_ready())
        under_test.login(allow_tty_prompt=True, allow_open_browser=False)
        self.assertTrue(under_test.request_authenticator_is_ready())


class TestAuthIsInitialized_deviceCodeAuthClient(unittest.TestCase, IsInitializedTestBaseForOAuth2Client):
    def setUp(self):
        super()._initMockStorage()

    def test_session_is_initialized__in_memory__without_initial_credential_data(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-device-code-without-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="some-random-utest-name",
            save_profile_config=False,
            save_token_file=False,
        )
        self.assertFalse(under_test.request_authenticator_is_ready())

    def test_session_is_initialized_by_existing_credential__in_memory__with_initial_credential_data(self):
        # Not expected to be a common case.  If you have a saved credential, you should be using storage.
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-device-code-without-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="some-random-utest-name",
            save_profile_config=False,
            save_token_file=False,
            initial_token_data=_mock_oidc_credential_data(),
        )
        self.assertTrue(under_test.request_authenticator_is_ready())

    def test_session_is_initialized_by_existing_credential__with_storage__with_stored_credential_data(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_storage["storage-utest-device-code-with-credential"][
                "client-config"
            ],
            storage_provider=self.mock_storage_provider,
            profile_name="storage-utest-device-code-with-credential",
            save_profile_config=True,
            save_token_file=True,
            initial_token_data=None,
        )
        self.assertTrue(under_test.request_authenticator_is_ready())

    @mock.patch("requests.sessions.Session.post", side_effect=mock_oauth_http_svc)
    @mock.patch("requests.sessions.Session.get", side_effect=mock_oauth_http_svc)
    def test_session_is_initialized_by_login__in_memory__login_causes_session_to_be_initialized(
        self, mock_http_get, mock_http_post
    ):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-device-code-without-credential"]["client-config"],
            storage_provider=self.mock_storage_provider,
            profile_name="some-random-utest-name",
            save_profile_config=False,
            save_token_file=False,
        )
        self.assertFalse(under_test.request_authenticator_is_ready())
        device_login_initiate = under_test.device_login_initiate(allow_tty_prompt=True, allow_open_browser=False)
        under_test.device_login_complete(device_login_initiate)
        self.assertTrue(under_test.request_authenticator_is_ready())

    @pytest.mark.xfail(reason="TODO: Custom storage providers used by this test not yet supported for client profiles")
    @mock.patch("requests.sessions.Session.post", side_effect=mock_oauth_http_svc)
    @mock.patch("requests.sessions.Session.get", side_effect=mock_oauth_http_svc)
    def test_session_is_initialized_by_login__with_storage__profile_from_storage(self, mock_http_get, mock_http_post):
        under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt="storage-utest-device-code-without-credential",
            save_profile_config=True,
            save_token_file=True,
            # storage_provider=self.mock_storage_provider,
        )
        self.assertFalse(under_test.request_authenticator_is_ready())
        under_test.login(allow_tty_prompt=True, allow_open_browser=False)
        self.assertTrue(under_test.request_authenticator_is_ready())


class TestAuthIsInitialized_m2mAuthClient(unittest.TestCase, IsInitializedTestBaseForOAuth2Client):
    def setUp(self):
        super()._initMockStorage()

    def test_session_is_initialized_by_client_config__in_memory(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config=self.test_client_data_in_memory["mem-utest-m2m-without-credential"]["client-config"],
            save_token_file=False,
            save_profile_config=False,
            profile_name="some-random-utest-name",
            # storage_provider=self.mock_storage_provider, # Should not be used or matter in this case.
        )
        self.assertTrue(under_test.request_authenticator_is_ready())

    @pytest.mark.xfail(reason="TODO: Custom storage providers used by this test not yet supported for client profiles")
    def test_session_is_initialized_by_client_config__from_storage_profile(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt="storage-utest-m2m-without-credential"
        )
        self.assertTrue(under_test.request_authenticator_is_ready())
