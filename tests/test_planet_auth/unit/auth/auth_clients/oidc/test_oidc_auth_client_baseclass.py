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
from typing import Union
from unittest import mock
from unittest.mock import MagicMock

import pytest as pytest

from planet_auth.auth_client import AuthClientConfigException, AuthClientException
from planet_auth.credential import Credential
from planet_auth.oidc.api_clients.api_client import EnricherPayloadType, EnricherReturnType
from planet_auth.oidc.auth_client import (
    OidcAuthClient,
    OidcAuthClientConfig,
)
from planet_auth.oidc.auth_client_with_client_pubkey import OidcAuthClientWithPubKeyClientConfig
from planet_auth.oidc.auth_client_with_client_secret import OidcAuthClientWithClientSecretClientConfig
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.request_authenticator import CredentialRequestAuthenticator, SimpleInMemoryRequestAuthenticator
from tests.test_planet_auth.util import tdata_resource_file_path

TEST_CLIENT_ID = "_FAKE_CLIENT_ID_"
TEST_CLIENT_SECRET = "_FAKE_CLIENT_SECRET_"
TEST_ACCESS_TOKEN = "_FAKE_ACCESS_TOKEN_"
TEST_TOKEN_FILE = "/test/token.json"
TEST_FAKE_TOKEN_FILE_DATA = {
    "token_type": "Bearer",
    "expires_in": 3600,
    "access_token": "_dummy_access_token_",
    "scope": "offline_access profile openid",
    "refresh_token": "_dummy_refresh_token_",
    "id_token": "_dummy_id_token_",
}

TEST_AUTH_SERVER = "https://blackhole.unittest.planet.com/fake_authserver"
TEST_DISCOVERED_AUTH_SERVER_BASE = "https://auth.unittest.planet.com"
TEST_OVERRIDE_AUTH_SERVER_BASE = "https://auth_override.unittest.planet.com"
TEST_FAKE_OIDC_DISCOVERY = {
    "issuer": TEST_DISCOVERED_AUTH_SERVER_BASE,
    "authorization_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/authorize",
    "token_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/token",
    "userinfo_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/userinfo",
    "registration_endpoint": "https://account.planet.com/oauth2/clients",
    "jwks_uri": TEST_DISCOVERED_AUTH_SERVER_BASE + "/jwks",
    "response_types_supported": [
        "code",
        "id_token",
        "code id_token",
        "code token",
        "id_token token",
        "code id_token token",
    ],
    "response_modes_supported": ["query", "fragment", "form_post", "okta_post_message"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "urn:ietf:params:oauth:grant-type:device_code",
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access", "device_sso"],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
    ],
    "claims_supported": [
        "iss",
        "ver",
        "sub",
        "aud",
        "iat",
        "exp",
        "jti",
        "auth_time",
        "amr",
        "idp",
        "nonce",
        "name",
        "nickname",
        "preferred_username",
        "given_name",
        "middle_name",
        "family_name",
        "email",
        "email_verified",
        "profile",
        "zoneinfo",
        "locale",
        "address",
        "phone_number",
        "picture",
        "website",
        "gender",
        "birthdate",
        "updated_at",
        "at_hash",
        "c_hash",
    ],
    "code_challenge_methods_supported": ["S256"],
    "introspection_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/introspection",
    "introspection_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
    ],
    "revocation_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/revocation",
    "revocation_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
    ],
    "end_session_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/logout",
    "request_parameter_supported": True,
    "request_object_signing_alg_values_supported": [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
    ],
    "device_authorization_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/device_auth",
}

TEST_FAKE_OIDC_DISCOVERY_NO_ENDPOINTS = {
    "issuer": TEST_DISCOVERED_AUTH_SERVER_BASE,
    "registration_endpoint": "https://account.planet.com/oauth2/clients",
    "response_types_supported": [
        "code",
        "id_token",
        "code id_token",
        "code token",
        "id_token token",
        "code id_token token",
    ],
    "response_modes_supported": ["query", "fragment", "form_post", "okta_post_message"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "urn:ietf:params:oauth:grant-type:device_code",
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access", "device_sso"],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
    ],
    "claims_supported": [
        "iss",
        "ver",
        "sub",
        "aud",
        "iat",
        "exp",
        "jti",
        "auth_time",
        "amr",
        "idp",
        "nonce",
        "name",
        "nickname",
        "preferred_username",
        "given_name",
        "middle_name",
        "family_name",
        "email",
        "email_verified",
        "profile",
        "zoneinfo",
        "locale",
        "address",
        "phone_number",
        "picture",
        "website",
        "gender",
        "birthdate",
        "updated_at",
        "at_hash",
        "c_hash",
    ],
    "code_challenge_methods_supported": ["S256"],
    "end_session_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/logout",
    "request_parameter_supported": True,
    "request_object_signing_alg_values_supported": [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
    ],
    "device_authorization_endpoint": TEST_DISCOVERED_AUTH_SERVER_BASE + "/device/authorize",
}


def mocked_oidc_discovery(**kwargs):
    return TEST_FAKE_OIDC_DISCOVERY


def mocked_oidc_discovery_no_endpoints(**kwargs):
    return TEST_FAKE_OIDC_DISCOVERY_NO_ENDPOINTS


class OidcBaseTestHarnessClientConfig(OidcAuthClientConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class OidcBaseTestHarnessAuthClient(OidcAuthClient):
    def __init__(self, client_config: OidcBaseTestHarnessClientConfig):
        super().__init__(client_config)
        self._test_client_config = client_config

    def _client_auth_enricher(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        return raw_payload, None

    def _oidc_flow_login(
        self, allow_open_browser, allow_tty_prompt, requested_scopes, requested_audiences, extra, **kwargs
    ) -> FileBackedOidcCredential:
        return FileBackedOidcCredential(data=TEST_FAKE_TOKEN_FILE_DATA)

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> CredentialRequestAuthenticator:
        return SimpleInMemoryRequestAuthenticator(token_body=TEST_ACCESS_TOKEN)

    def can_login_unattended(self) -> bool:
        return False


def mocked_pem_load_error(key_data, **kwargs):
    return None


class AuthClientConfigBaseTest(unittest.TestCase):
    def test_authorization_callback_authorization_empty(self):
        under_test = OidcAuthClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID)
        under_test.check()
        self.assertIsNone(under_test.authorization_callback_acknowledgement_data())

    def test_authorization_callback_authorization_from_literal(self):
        under_test = OidcAuthClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            authorization_callback_acknowledgement="test acknowledgement literal",
        )
        under_test.check()
        self.assertEqual(under_test.authorization_callback_acknowledgement_data(), "test acknowledgement literal")
        # Test coverage antidepressants: Coverate wants us to walk both branches of the lazy load
        self.assertEqual(under_test.authorization_callback_acknowledgement_data(), "test acknowledgement literal")

    def test_authorization_callback_authorization_from_file(self):
        resource_path = tdata_resource_file_path("resources/authorization_callback_acknowledgement.html")
        with open(resource_path, encoding="UTF-8") as resource_file:
            resource_file_str = resource_file.read()
            under_test = OidcAuthClientConfig(
                auth_server=TEST_AUTH_SERVER,
                client_id=TEST_CLIENT_ID,
                authorization_callback_acknowledgement_file=resource_path,
            )
            under_test.check()
            self.assertEqual(under_test.authorization_callback_acknowledgement_data(), resource_file_str)

    def test_authorization_callback_authorization_both_literal_and_file_set(self):
        # Code literal beats file
        resource_path = tdata_resource_file_path("resources/authorization_callback_acknowledgement.html")
        under_test = OidcAuthClientConfig(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            authorization_callback_acknowledgement="test acknowledgement literal",
            authorization_callback_acknowledgement_file=resource_path,
        )
        under_test.check()
        self.assertEqual(under_test.authorization_callback_acknowledgement_data(), "test acknowledgement literal")

    def test_required_config_fields(self):
        under_test = OidcAuthClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID)
        under_test.check()  # no throw

        under_test = OidcAuthClientConfig(client_id=TEST_CLIENT_ID)
        with self.assertRaises(AuthClientConfigException):
            under_test.check()

        under_test = OidcAuthClientConfig(auth_server=TEST_AUTH_SERVER)
        with self.assertRaises(AuthClientConfigException):
            under_test.check()

    def test_audiences_valid_value(self):
        under_test = OidcAuthClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, audiences=None)
        under_test.check()  # no throw

        under_test = OidcAuthClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, audiences=[])
        under_test.check()  # no throw

        under_test = OidcAuthClientConfig(auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, audiences=["aud1"])
        under_test.check()  # no throw

        # under_test = OidcAuthClientConfig(
        #     auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, audiences=""  # Falsy value is not list type
        # )
        # with self.assertRaises(AuthClientConfigException):
        #     under_test.check()

        under_test = OidcAuthClientConfig(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, audiences="value_is_not_list_type"
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.check()

        under_test = OidcAuthClientConfig(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, audiences=["aud1", "aud2"]
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class OidcAuthClientWithClientSecretClientConfigTest(unittest.TestCase):
    class TestConfigClass(OidcAuthClientWithClientSecretClientConfig):
        pass  # just test the ABC base.

    def test_secret_configured(self):
        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_secret=TEST_CLIENT_SECRET
        )
        under_test.check()
        self.assertEqual(TEST_CLIENT_SECRET, under_test.client_secret())

    def test_no_secret_configured(self):
        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class OidcAuthClientWithPubKeyClientConfigTest(unittest.TestCase):
    class TestConfigClass(OidcAuthClientWithPubKeyClientConfig):
        pass  # just test the ABC base.

    @classmethod
    def setUpClass(cls):
        cls.privkey_password = "password"
        cls.privkey_file_path = tdata_resource_file_path("keys/keypair1_priv.test_pem")
        with open(cls.privkey_file_path, encoding="UTF-8") as key_file:
            cls.privkey_literal_str = key_file.read()

        cls.privkey_file_path_nopassword = tdata_resource_file_path("keys/keypair1_priv_nopassword.test_pem")
        with open(cls.privkey_file_path_nopassword, encoding="UTF-8") as key_file:
            cls.privkey_literal_str_nopassword = key_file.read()

    def _assert_rsa_keys_equal(self, key1, key2):
        # We are not validating the crypto libs. We assume if both keys
        # loaded without throwing and look similar, our code is working as
        # expected.
        self.assertEqual(key1.key_size, key2.key_size)

    def test_key_loads_from_literal_or_file(self):
        under_test_literal = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_privkey=self.privkey_literal_str_nopassword
        )
        under_test_literal.check()

        under_test_filebacked = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_file=self.privkey_file_path_nopassword,
        )
        under_test_filebacked.check()

        self._assert_rsa_keys_equal(
            under_test_filebacked.client_privkey_data(), under_test_literal.client_privkey_data()
        )

    def test_key_loads_with_or_without_password_literal(self):
        under_test_nopw = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_privkey=self.privkey_literal_str_nopassword
        )
        under_test_nopw.check()

        under_test_pw = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey=self.privkey_literal_str,
            client_privkey_password=self.privkey_password,
        )
        under_test_pw.check()

        key_nopw = under_test_nopw.client_privkey_data()
        key_pw = under_test_pw.client_privkey_data()
        self._assert_rsa_keys_equal(key_pw, key_nopw)

    def test_key_loads_with_or_without_password_filebacked(self):
        under_test_nopw = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_file=self.privkey_file_path_nopassword,
        )
        under_test_nopw.check()

        under_test_pw = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_file=self.privkey_file_path,
            client_privkey_password=self.privkey_password,
        )
        under_test_pw.check()

        key_nopw = under_test_nopw.client_privkey_data()
        key_pw = under_test_pw.client_privkey_data()
        self._assert_rsa_keys_equal(key_pw, key_nopw)

    def test_bad_password_throws(self):
        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_password=None,
            client_privkey=self.privkey_literal_str,
        )
        under_test.check()
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_password="bad password",
            client_privkey=self.privkey_literal_str,
        )
        under_test.check()
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_password=None,
            client_privkey_file=self.privkey_file_path,
        )
        under_test.check()
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_password="bad password",
            client_privkey_file=self.privkey_file_path,
        )
        under_test.check()
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

    @mock.patch("cryptography.hazmat.primitives.serialization.load_pem_private_key", mocked_pem_load_error)
    def test_unexpected_keyload_restult(self):
        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER, client_id=TEST_CLIENT_ID, client_privkey=self.privkey_literal_str_nopassword
        )
        under_test.check()
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey_file=self.privkey_file_path_nopassword,
        )
        under_test.check()
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

    def test_no_key_configured(self):
        under_test = self.TestConfigClass(
            auth_server=TEST_AUTH_SERVER,
            client_id=TEST_CLIENT_ID,
            client_privkey=None,
            client_privkey_file=None,
            client_privkey_password=None,
        )
        with self.assertRaises(AuthClientConfigException):
            under_test.client_privkey_data()

    def test_lazy_load_only_once(self):
        # pylint: disable=fixme
        # FIXME: wrapping the object in this way doesn't seem to actually
        #   catch call counts for internal method calls.  Stepping through
        #   debugger seems to indicate proper behavior.
        under_test = MagicMock(
            wraps=self.TestConfigClass(
                auth_server=TEST_AUTH_SERVER,
                client_id=TEST_CLIENT_ID,
                client_privkey_file=self.privkey_file_path_nopassword,
            )
        )
        under_test.check()
        self.assertEqual(0, under_test._load_private_key.call_count)
        under_test.client_privkey_data()
        # self.assertEqual(1, under_test._load_private_key.call_count)
        under_test.client_privkey_data()
        # self.assertEqual(1, under_test._load_private_key.call_count)


@mock.patch(
    "planet_auth.oidc.api_clients.discovery_api_client.DiscoveryApiClient.discovery",
    side_effect=mocked_oidc_discovery,
)
class AuthClientBaseTest(unittest.TestCase):
    def setUp(self):
        self.defaults_under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                audiences=["audience_from_client_config_1"],
                # audiences=["audience_from_client_config_1", "audience_from_client_config_2"],
            )
        )
        self.oidc_test_credential = FileBackedOidcCredential(data=TEST_FAKE_TOKEN_FILE_DATA)

    def test_oidc_discovery_override_authorization(self, mocked_discovery):
        # OIDC discovery is intended to be JIT in the base class.
        # When an override is provided, 1) that discovery should not happen
        # (some OIDC providers don't offer discovery, so it would fail),
        # and 2) the override should be used, even if discovery was
        # previously successful for another endpoint.
        #
        # This should be tested for each endpoint we support:
        #   authorization_endpoint  (This one is an oddball, since it doesn't
        #                            make HTTP requests the same way)
        #   introspection_endpoint
        #   jwks_endpoint
        #   revocation_endpoint
        #   userinfo_endpoint
        #   token_endpoint

        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                authorization_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/authorize",
            )
        )
        api_client = under_test.authorization_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/authorize", api_client._authorization_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.authorization_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/authorize", api_client._authorization_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                authorization_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/authorize",
            )
        )
        under_test._discovery()
        api_client = under_test.authorization_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/authorize", api_client._authorization_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.authorization_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/authorize", default_api_client._authorization_uri)

    def test_oidc_discovery_override_device_authorization(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                device_authorization_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/device_auth",
            )
        )
        api_client = under_test.device_authorization_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/device_auth", api_client._endpoint_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.device_authorization_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/device_auth", api_client._endpoint_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                device_authorization_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/device_auth",
            )
        )
        under_test._discovery()
        api_client = under_test.device_authorization_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/device_auth", api_client._endpoint_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.device_authorization_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/device_auth", default_api_client._endpoint_uri)

    def test_oidc_discovery_override_introspection(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                introspection_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/introspection",
            )
        )
        api_client = under_test.introspection_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/introspection", api_client._endpoint_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.introspection_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/introspection", api_client._endpoint_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                introspection_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/introspection",
            )
        )
        under_test._discovery()
        api_client = under_test.introspection_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/introspection", api_client._endpoint_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.introspection_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/introspection", default_api_client._endpoint_uri)

    def test_oidc_discovery_override_jwks(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                jwks_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/jwks",
            )
        )
        api_client = under_test.jwks_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/jwks", api_client._endpoint_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.jwks_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/jwks", api_client._endpoint_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                jwks_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/jwks",
            )
        )
        under_test._discovery()
        api_client = under_test.jwks_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/jwks", api_client._endpoint_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.jwks_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/jwks", default_api_client._endpoint_uri)

    def test_oidc_discovery_override_revocation(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                revocation_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/revocation",
            )
        )
        api_client = under_test.revocation_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/revocation", api_client._endpoint_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.revocation_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/revocation", api_client._endpoint_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                revocation_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/revocation",
            )
        )
        under_test._discovery()
        api_client = under_test.revocation_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/revocation", api_client._endpoint_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.revocation_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/revocation", default_api_client._endpoint_uri)

    def test_oidc_discovery_override_userinfo(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                userinfo_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/userinfo",
            )
        )
        api_client = under_test.userinfo_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/userinfo", api_client._endpoint_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.userinfo_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/userinfo", api_client._endpoint_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                userinfo_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/userinfo",
            )
        )
        under_test._discovery()
        api_client = under_test.userinfo_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/userinfo", api_client._endpoint_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.userinfo_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/userinfo", default_api_client._endpoint_uri)

    def test_oidc_discovery_override_token(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                token_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/token",
            )
        )
        api_client = under_test.token_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/token", api_client._endpoint_uri)
        self.assertEqual(0, mocked_discovery.call_count)

        # discovery after the initial overridden client fetch (above) tests
        # that it's not clobbered by discovery
        under_test._discovery()
        api_client = under_test.token_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/token", api_client._endpoint_uri)

        # Discovery before the initial fetch test that it's not preempted by
        # a prior discovery.
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                token_endpoint=TEST_OVERRIDE_AUTH_SERVER_BASE + "/token",
            )
        )
        under_test._discovery()
        api_client = under_test.token_client()
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/token", api_client._endpoint_uri)

        # And finally, test default behavior:
        default_api_client = self.defaults_under_test.token_client()
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE + "/token", default_api_client._endpoint_uri)

    def test_issuer_discovery_override(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                issuer=TEST_OVERRIDE_AUTH_SERVER_BASE + "/override_issuer",
            )
        )
        self.assertEqual(TEST_OVERRIDE_AUTH_SERVER_BASE + "/override_issuer", under_test._issuer())
        self.assertEqual(0, mocked_discovery.call_count)

        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE, client_id=TEST_CLIENT_ID)
        )
        self.assertEqual(TEST_DISCOVERED_AUTH_SERVER_BASE, under_test._issuer())
        self.assertEqual(1, mocked_discovery.call_count)

        # second call doesn't re-do discovery
        under_test._issuer()
        self.assertEqual(1, mocked_discovery.call_count)

    def test_token_validator_created_once(self, mocked_discovery):
        under_test = self.defaults_under_test
        token_validator = under_test._token_validator()
        self.assertIsNotNone(token_validator)
        token_validator2 = under_test._token_validator()
        self.assertEqual(token_validator, token_validator2)

    #
    # The base client implementation of the following is pretty much
    # one liner pass through.  These nothing-burger tests are mostly
    # to goose the coverage targets, and would really only catch
    # gross errors in the pass through implementation. These are
    # better tested in end-to-end tests.
    #
    @mock.patch("planet_auth.oidc.api_clients.token_api_client.TokenApiClient.get_token_from_refresh")
    def test_refresh(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        credential = under_test.refresh(self.oidc_test_credential.refresh_token())
        self.assertIsInstance(credential, FileBackedOidcCredential)
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.api_clients.introspect_api_client.IntrospectionApiClient.validate_access_token")
    def test_validate_access_token(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.validate_access_token_remote(self.oidc_test_credential.access_token())
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.token_validator.TokenValidator.validate_token")
    def test_validate_access_token_local(self, mock_validate_token, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.validate_access_token_local(
            self.oidc_test_credential.access_token(), required_audience="audience_from_validate_call"
        )
        self.assertEqual(1, mock_validate_token.call_count)
        args, kwargs = mock_validate_token.call_args
        self.assertEqual("audience_from_validate_call", kwargs.get("audience"))

    @mock.patch("planet_auth.oidc.token_validator.TokenValidator.validate_token")
    def test_validate_access_token_local_default_audience_from_config(self, mock_validate_token, mocked_discovery):
        under_test_with_username_password = self.defaults_under_test
        under_test_with_username_password.validate_access_token_local(self.oidc_test_credential.access_token())
        self.assertEqual(1, mock_validate_token.call_count)
        args, kwargs = mock_validate_token.call_args
        self.assertEqual("audience_from_client_config_1", kwargs.get("audience"))

    def test_validate_access_token_no_audience_fails(self, mock_validate_token):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                # audiences=["audience_from_client_config_1"],
                # audiences=["audience_from_client_config_1", "audience_from_client_config_2"],
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.validate_access_token_local(self.oidc_test_credential.access_token())

    @pytest.mark.xfail(
        reason="This test check for a runtime error during token validation when the required audience is ambiguous."
        " Currently, the code prevents this from being a legal config, so rather than the runtime AuthClientException exception,"
        " a config time AuthClientConfigException exception is thrown."
        " Should configuration ever loosen generally, this test should remain and no longer be marked xfail"
        " since a runtime error should be thrown."
    )
    def test_validate_access_token_ambiguous_audience_fails(self, mock_validate_token):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                # audiences=["audience_from_client_config_1"],
                audiences=["audience_from_client_config_1", "audience_from_client_config_2"],
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.validate_access_token_local(self.oidc_test_credential.access_token())

    @mock.patch("planet_auth.oidc.api_clients.introspect_api_client.IntrospectionApiClient.validate_id_token")
    def test_validate_id_token(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.validate_id_token_remote(self.oidc_test_credential.id_token())
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.token_validator.TokenValidator.validate_id_token")
    def test_validate_id_token_local(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.validate_id_token_local(self.oidc_test_credential.id_token())
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.api_clients.introspect_api_client.IntrospectionApiClient.validate_refresh_token")
    def test_validate_refresh_token(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.validate_refresh_token_remote(self.oidc_test_credential.refresh_token())
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.api_clients.revocation_api_client.RevocationApiClient.revoke_access_token")
    def test_revoke_access_token(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.revoke_access_token(self.oidc_test_credential.access_token())
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.api_clients.revocation_api_client.RevocationApiClient.revoke_refresh_token")
    def test_revoke_refresh_token(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.revoke_refresh_token(self.oidc_test_credential.refresh_token())
        self.assertEqual(1, mock_api_client.call_count)

    @mock.patch("planet_auth.oidc.api_clients.userinfo_api_client.UserinfoApiClient.userinfo_from_access_token")
    def test_userinfo_from_access_token(self, mock_api_client, mocked_discovery):
        under_test = self.defaults_under_test
        under_test.userinfo_from_access_token(self.oidc_test_credential.access_token())
        self.assertEqual(1, mock_api_client.call_count)

    def test_get_scopes(self, mocked_discovery):
        under_test = self.defaults_under_test
        test_scopes = under_test.get_scopes()
        self.assertEqual(TEST_FAKE_OIDC_DISCOVERY["scopes_supported"], test_scopes)


@mock.patch(
    "planet_auth.oidc.api_clients.discovery_api_client.DiscoveryApiClient.discovery",
    side_effect=mocked_oidc_discovery_no_endpoints,
)
class AuthClientBaseTestDiscoveryDoesNotAdvertiseEndpoints(unittest.TestCase):
    def setUp(self):
        self.defaults_under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
                audiences=["audience_from_client_config_1"],
                # audiences=["audience_from_client_config_1", "audience_from_client_config_2"],
            )
        )
        self.oidc_test_credential = FileBackedOidcCredential(data=TEST_FAKE_TOKEN_FILE_DATA)

    def test_oidc_discovery_no_authorization_endpoint(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.authorization_client()

    def test_oidc_discovery_no_introspection_endpoint(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.introspection_client()

    def test_oidc_discovery_no_jwks_endpoint(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.jwks_client()

    def test_oidc_discovery_no_revocation_endpoint(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.revocation_client()

    def test_oidc_discovery_no_userinfo_endpoint(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.userinfo_client()

    def test_oidc_discovery_no_token_endpoint(self, mocked_discovery):
        under_test = OidcBaseTestHarnessAuthClient(
            OidcBaseTestHarnessClientConfig(
                auth_server=TEST_DISCOVERED_AUTH_SERVER_BASE,
                client_id=TEST_CLIENT_ID,
            )
        )
        with self.assertRaises(AuthClientException):
            under_test.token_client()
