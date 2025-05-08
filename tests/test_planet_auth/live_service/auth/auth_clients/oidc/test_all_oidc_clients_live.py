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

import pytest
from typing import Tuple

from planet_auth.auth_client import AuthClientConfig
from planet_auth.oidc.auth_client import OidcAuthClient
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.api_clients.introspect_api_client import IntrospectionApiException
from tests.test_planet_auth.util import tdata_resource_file_path

from planet_auth.auth import Auth

CLIENT_CONFIG_FOR_USER_LOGIN = [
    "oauth_pkce_auth_code.json",
    "oauth_pkce_auth_code_client_secret.sops.json",
    "oauth_pkce_auth_code_pubkey.sops.json",
    "oauth_resource_owner.sops.json",
    "oauth_resource_owner_client_secret.sops.json",
    "oauth_resource_owner_client_pubkey.sops.json",
]

CLIENT_CONIGS_FOR_CLIENT_LOGIN = [
    "oauth_client_credentials_client_secret.sops.json",
    "oauth_client_credentials_pubkey_literal.sops.json",
]

## from tests.util import is_not_interactive_shell
## @pytest.mark.skipif(condition=is_not_interactive_shell(), reason="Skipping test in non-interactive shell")


#
# WARNING:
#    These test do not run in parallel well.  There is contention over callback the listening port.
#    These tests may also require user interaction.  These are here to make it convenient to run
#    a battery of tests manually against a wide swath of client configs.  But, these are not
#    at this point fire and forget tests.
#
class TestLiveService:
    @staticmethod
    def auth_from_test_resource_file(resource_file) -> Tuple[Auth, OidcAuthClient, FileBackedOidcCredential]:
        test_client_conf_file = tdata_resource_file_path("auth_client_configs/live_service/{}".format(resource_file))
        auth = Auth.initialize_from_config(client_config=AuthClientConfig.from_file(test_client_conf_file))
        oidc_auth_client = auth.auth_client()
        token = oidc_auth_client.login()
        return auth, oidc_auth_client, token

    @staticmethod
    def revoke_test_token(auth_client: OidcAuthClient, token: FileBackedOidcCredential):
        if token:
            if token.refresh_token():
                auth_client.revoke_refresh_token(token.refresh_token())
            if token.access_token():
                auth_client.revoke_access_token(token.access_token())

    @pytest.mark.parametrize("client_config_file", CLIENT_CONFIG_FOR_USER_LOGIN)
    def test_user_login(self, client_config_file):
        """
        Test OIDC flows that login for a user
        """
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            assert token.access_token() is not None
            assert token.id_token() is not None
            assert token.refresh_token() is not None
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)

    @pytest.mark.parametrize("client_config_file", CLIENT_CONIGS_FOR_CLIENT_LOGIN)
    def test_client_login(self, client_config_file):
        """
        Test OIDC flows that login for the client itself
        """
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            assert token.access_token() is not None
            assert token.id_token() is None
            assert token.refresh_token() is None
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)

    @pytest.mark.parametrize("client_config_file", CLIENT_CONFIG_FOR_USER_LOGIN)
    def test_validate_id_token(self, client_config_file):
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            validation = oidc_client_under_test.validate_id_token_remote(token.id_token())
            assert isinstance(validation.get("active"), bool)
            assert validation.get("active")
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)

    @pytest.mark.parametrize("client_config_file", CLIENT_CONFIG_FOR_USER_LOGIN + CLIENT_CONIGS_FOR_CLIENT_LOGIN)
    def test_validate_access_token(self, client_config_file):
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            validation = oidc_client_under_test.validate_access_token_remote(token.access_token())
            assert isinstance(validation.get("active"), bool)
            assert validation.get("active")
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)

    @pytest.mark.parametrize("client_config_file", CLIENT_CONFIG_FOR_USER_LOGIN + CLIENT_CONIGS_FOR_CLIENT_LOGIN)
    def test_revoke_access_token(self, client_config_file):
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            oidc_client_under_test.revoke_access_token(token.access_token())
            with pytest.raises(IntrospectionApiException):
                oidc_client_under_test.validate_access_token_remote(token.access_token())
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)

    @pytest.mark.parametrize("client_config_file", CLIENT_CONFIG_FOR_USER_LOGIN)
    def test_validate_refresh_token(self, client_config_file):
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            validation = oidc_client_under_test.validate_refresh_token_remote(token.refresh_token())
            assert isinstance(validation.get("active"), bool)
            assert validation.get("active")
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)

    @pytest.mark.parametrize("client_config_file", CLIENT_CONFIG_FOR_USER_LOGIN)
    def test_revoke_refresh_token(self, client_config_file):
        auth_context, oidc_client_under_test, token = self.auth_from_test_resource_file(client_config_file)
        try:
            oidc_client_under_test.revoke_refresh_token(token.refresh_token())
            with pytest.raises(IntrospectionApiException):
                oidc_client_under_test.validate_refresh_token_remote(token.refresh_token())
        finally:
            self.revoke_test_token(auth_client=oidc_client_under_test, token=token)
