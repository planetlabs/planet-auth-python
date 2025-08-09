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
from typing import Optional, Union

import planet_auth
from planet_auth.auth_client import AuthClientConfig, AuthClient, AuthClientException
from planet_auth.credential import Credential
from planet_auth.oidc.auth_clients.auth_code_flow import (
    AuthCodeClientConfig,
    AuthCodeWithPubKeyClientConfig,
    AuthCodeWithClientSecretClientConfig,
)
from planet_auth.oidc.auth_clients.device_code_flow import (
    DeviceCodeClientConfig,
    DeviceCodeWithClientSecretClientConfig,
    DeviceCodeWithPubKeyClientConfig,
)
from planet_auth.oidc.auth_clients.client_credentials_flow import (
    ClientCredentialsClientSecretClientConfig,
    ClientCredentialsPubKeyClientConfig,
)
from planet_auth.oidc.auth_clients.client_validator import OidcClientValidatorAuthClientConfig
from planet_auth.oidc.auth_clients.resource_owner_flow import (
    ResourceOwnerClientConfig,
    ResourceOwnerWithClientSecretClientConfig,
    ResourceOwnerWithPubKeyClientConfig,
)
from planet_auth.planet_legacy.auth_client import PlanetLegacyAuthClientConfig
from planet_auth.request_authenticator import CredentialRequestAuthenticator
from planet_auth.static_api_key.auth_client import StaticApiKeyAuthClientConfig
from planet_auth.none.noop_auth import NoOpAuthClientConfig
from tests.test_planet_auth.util import tdata_resource_file_path


class AuthClientConfigTestImpl(AuthClientConfig):
    @classmethod
    def meta(cls):
        return {}


class AuthClientConfigInvalidImpl(AuthClientConfig):
    @classmethod
    def meta(cls):
        return {}


class AuthClientTestImpl(AuthClient):
    def __init__(self, client_config: AuthClientConfigTestImpl):
        super().__init__(client_config)
        self._test_client_config = client_config

    def login(
        self, allow_open_browser: Optional[bool] = False, allow_tty_prompt: Optional[bool] = False, **kwargs
    ) -> Credential:
        assert 0  # abstract method not under test

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> CredentialRequestAuthenticator:
        # return SimpleInMemoryRequestAuthenticator(token_body=None)
        assert 0  # abstract method not under test

    def can_login_unattended(self) -> bool:
        return False


class TestAuthClientBase(unittest.TestCase):
    def test_no_impl_exception(self):
        under_test = AuthClientTestImpl(AuthClientConfigTestImpl())

        with self.assertRaises(AuthClientException):
            under_test.refresh(None, None)

        with self.assertRaises(AuthClientException):
            under_test.validate_access_token_remote(None)

        with self.assertRaises(AuthClientException):
            under_test.validate_access_token_local(None, None)

        with self.assertRaises(AuthClientException):
            under_test.validate_id_token_remote(None)

        with self.assertRaises(AuthClientException):
            under_test.validate_id_token_local(None)

        with self.assertRaises(AuthClientException):
            under_test.validate_refresh_token_remote(None)

        with self.assertRaises(AuthClientException):
            under_test.revoke_access_token(None)

        with self.assertRaises(AuthClientException):
            under_test.revoke_refresh_token(None)

        with self.assertRaises(AuthClientException):
            under_test.device_login_initiate()

        with self.assertRaises(AuthClientException):
            under_test.device_login_complete({})

        with self.assertRaises(AuthClientException):
            under_test.userinfo_from_access_token(None)

        with self.assertRaises(AuthClientException):
            under_test.get_scopes()


class ClientFactoryTest(unittest.TestCase):
    def test_create_pkce_auth_code_client(self):
        self.assertIsInstance(
            AuthClient.from_config(AuthCodeClientConfig(auth_server="dummy", client_id="dummy", redirect_uri="dummy")),
            planet_auth.oidc.auth_clients.auth_code_flow.AuthCodeAuthClient,
        )

    def test_create_pkce_auth_code_client_secret_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                AuthCodeWithClientSecretClientConfig(
                    auth_server="dummy", client_id="dummy", redirect_uri="dummy", client_secret="dummy"
                )
            ),
            planet_auth.oidc.auth_clients.auth_code_flow.AuthCodeWithClientSecretAuthClient,
        )

    def test_create_pkce_auth_code_pubkey_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                AuthCodeWithPubKeyClientConfig(
                    auth_server="dummy", client_id="dummy", redirect_uri="dummy", client_privkey="dummy"
                )
            ),
            planet_auth.oidc.auth_clients.auth_code_flow.AuthCodeWithPubKeyAuthClient,
        )

    def test_create_device_code_client(self):
        self.assertIsInstance(
            AuthClient.from_config(DeviceCodeClientConfig(auth_server="dummy", client_id="dummy")),
            planet_auth.oidc.auth_clients.device_code_flow.DeviceCodeAuthClient,
        )

    def test_create_device_code_client_secret_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                DeviceCodeWithClientSecretClientConfig(auth_server="dummy", client_id="dummy", client_secret="dummy")
            ),
            planet_auth.oidc.auth_clients.device_code_flow.DeviceCodeWithClientSecretAuthClient,
        )

    def test_create_device_code_pubkey_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                DeviceCodeWithPubKeyClientConfig(auth_server="dummy", client_id="dummy", client_privkey="dummy")
            ),
            planet_auth.oidc.auth_clients.device_code_flow.DeviceCodeWithPubKeyAuthClient,
        )

    def test_create_client_credentials_client_secret_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                ClientCredentialsClientSecretClientConfig(
                    auth_server="dummy", client_id="dummy", client_secret="dummy"
                )
            ),
            planet_auth.oidc.auth_clients.client_credentials_flow.ClientCredentialsClientSecretAuthClient,
        )

    def test_create_client_credentials_pubkey_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                ClientCredentialsPubKeyClientConfig(auth_server="dummy", client_id="dummy", client_privkey="dummy")
            ),
            planet_auth.oidc.auth_clients.client_credentials_flow.ClientCredentialsPubKeyAuthClient,
        )

    def test_create_resource_owner_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                ResourceOwnerClientConfig(auth_server="dummy", client_id="dummy", username="dummy", password="dummy")
            ),
            planet_auth.oidc.auth_clients.resource_owner_flow.ResourceOwnerAuthClient,
        )

    def test_create_resource_owner_with_client_secret_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                ResourceOwnerWithClientSecretClientConfig(
                    auth_server="dummy", client_id="dummy", username="dummy", password="dummy", client_secret="dummy"
                )
            ),
            planet_auth.oidc.auth_clients.resource_owner_flow.ResourceOwnerWithClientSecretAuthClient,
        )

    def test_create_resource_owner_with_pubkey_client(self):
        self.assertIsInstance(
            AuthClient.from_config(
                ResourceOwnerWithPubKeyClientConfig(
                    auth_server="dummy", client_id="dummy", username="dummy", password="dummy", client_privkey="dummy"
                )
            ),
            planet_auth.oidc.auth_clients.resource_owner_flow.ResourceOwnerWithPubKeyAuthClient,
        )

    def test_create_client_validator_client(self):
        self.assertIsInstance(
            AuthClient.from_config(OidcClientValidatorAuthClientConfig(auth_server="dummy")),
            planet_auth.oidc.auth_clients.client_validator.OidcClientValidatorAuthClient,
        )

    def test_create_planet_legacy_client(self):
        self.assertIsInstance(
            AuthClient.from_config(PlanetLegacyAuthClientConfig(legacy_auth_endpoint="dummy")),
            planet_auth.planet_legacy.auth_client.PlanetLegacyAuthClient,
        )

    def test_static_apikey_client(self):
        self.assertIsInstance(
            AuthClient.from_config(StaticApiKeyAuthClientConfig()),
            planet_auth.static_api_key.auth_client.StaticApiKeyAuthClient,
        )

    def test_noop_client(self):
        self.assertIsInstance(
            AuthClient.from_config(NoOpAuthClientConfig(extra_garbage_to_ignore="some_test_trash")),
            planet_auth.none.noop_auth.NoOpAuthClient,
        )

    def test_invalid_config_type(self):
        with self.assertRaises(AuthClientException):
            AuthClient.from_config(AuthClientConfigInvalidImpl())


class ConfigFactoryTest(unittest.TestCase):
    def test_pkce_auth_code_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/auth_code.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, AuthCodeClientConfig)

    def test_pkce_auth_code_secret_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/auth_code_secret.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, AuthCodeWithClientSecretClientConfig)

    def test_pkce_auth_code_pubkey_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/auth_code_pubkey.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, AuthCodeWithPubKeyClientConfig)

    def test_device_code_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/device_auth.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, DeviceCodeClientConfig)

    def test_device_code_secret_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/device_auth_secret.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, DeviceCodeWithClientSecretClientConfig)

    def test_device_code_pubkey_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/device_auth_pubkey.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, DeviceCodeWithPubKeyClientConfig)

    def test_client_credentials_client_secret_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/client_credentials_client_secret.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, ClientCredentialsClientSecretClientConfig)

    def test_client_credentials_pubkey_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/client_credentials_pubkey_file.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, ClientCredentialsPubKeyClientConfig)

    def test_resource_owner_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/resource_owner.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, ResourceOwnerClientConfig)

    def test_resource_owner_client_secret_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/resource_owner_secret.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, ResourceOwnerWithClientSecretClientConfig)

    def test_resource_owner_pubkey_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/resource_owner_pubkey.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, ResourceOwnerWithPubKeyClientConfig)

    def test_client_validator_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/client_validator.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, OidcClientValidatorAuthClientConfig)

    def test_static_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/static_api_key.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, StaticApiKeyAuthClientConfig)

    def test_noop_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/none.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, NoOpAuthClientConfig)

    def test_planet_legacy_config_from_file(self):
        file_path = tdata_resource_file_path("auth_client_configs/utest/planet_legacy.json")
        auth_client_config = AuthClientConfig.from_file(file_path)
        self.assertIsInstance(auth_client_config, PlanetLegacyAuthClientConfig)

    def test_invalid_config_type(self):
        with self.assertRaises(AuthClientException):
            AuthClientConfig.from_dict({"client_type": "__test_invalid__"})


class ValidateConfigMeta(unittest.TestCase):
    """
    Test config metadata used by the Auth classes themselves
    """

    def _check_meta_key_uniqueness(self, under_test_meta_key):
        under_test_meta_values = {}
        for under_test_config_type in AuthClientConfig._get_config_types():
            under_test_meta = under_test_config_type.meta()
            under_test_meta_value = under_test_meta.get(under_test_meta_key)
            self.assertIsNotNone(
                under_test_meta.get(under_test_meta_key),
                "Meta field {} is not set for type {}".format(under_test_meta_key, under_test_config_type),
            )
            self.assertIsNone(
                under_test_meta_values.get(under_test_meta.get(under_test_meta_key)),
                "Meta field {} must be unique across auth client config types.  Duplicate value '{}' found in '{}'".format(
                    under_test_meta_key, under_test_meta_value, under_test_config_type.__name__
                ),
            )
            under_test_meta_values[under_test_meta_value] = under_test_config_type.__name__

    def test_type_name_uniqueness(self):
        self._check_meta_key_uniqueness(AuthClientConfig.CLIENT_TYPE_KEY)

    def test_client_type_uniqueness(self):
        self._check_meta_key_uniqueness("auth_client_class")


class ValidateConfigMetaForCLI(unittest.TestCase):
    """
    Test config metadata used the the auth client CLI
    """

    def test_hints_are_well_formed(self):
        for under_test_config_type in AuthClientConfig._get_config_types():
            under_tests_hints = under_test_config_type.meta().get("config_hints")
            if under_tests_hints:
                for under_test_hint in under_tests_hints:
                    self.assertIsInstance(
                        under_test_hint,
                        dict,
                        "config_hints for type {} must be dict type".format(under_test_config_type.__name__),
                    )
                    # we check for truthy rather than not being none since empty strings are not really useful either
                    self.assertTrue(
                        under_test_hint.get("config_key"),
                        "Meta {} for {} missing a value for {}".format(
                            "config_hint", under_test_config_type.__name__, "config_key"
                        ),
                    )
                    self.assertTrue(
                        under_test_hint.get("config_key_name"),
                        "Meta {} for {} missing a value for {}".format(
                            "config_hint", under_test_config_type.__name__, "config_key_name"
                        ),
                    )
                    self.assertTrue(
                        under_test_hint.get("config_key_description"),
                        "Meta {} for {} missing a value for {}".format(
                            "config_hint", under_test_config_type.__name__, "config_key_description"
                        ),
                    )

    def test_no_duplicate_hints(self):
        for under_test_config_type in AuthClientConfig._get_config_types():
            under_tests_hints = under_test_config_type.meta().get("config_hints")
            if under_tests_hints:
                conf_hints = {}
                for under_test_hint in under_tests_hints:
                    self.assertIsNone(
                        conf_hints.get(under_test_hint.get("config_key")),
                        "Duplicate configuration hint for the key '{}' found in '{}'".format(
                            under_test_hint.get("config_key"), under_test_config_type.__name__
                        ),
                    )
                    conf_hints[under_test_hint.get("config_key")] = 1
