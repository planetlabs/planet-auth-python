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

import getpass
from abc import ABC
from typing import List, Optional

from planet_auth.auth_client import AuthClientException
from planet_auth.oidc.auth_client import (
    OidcAuthClientConfig,
    OidcAuthClient,
    OidcAuthClientWithNoneClientAuth,
)
from planet_auth.oidc.auth_client_with_client_pubkey import (
    OidcAuthClientWithClientPubkey,
    OidcAuthClientWithPubKeyClientConfig,
)
from planet_auth.oidc.auth_client_with_client_secret import (
    OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment,
    OidcAuthClientWithClientSecretClientConfig,
)
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.auth_client_default_authenticators import (
    OidcAuthClientWithRefreshOrReloginOidcTokenRequestAuthenticator,
)


# Resource owner flows are really not recommended.  We are handling the username/password,
# and there isn't a good reason for that.  Especially in environments with federated identity
# providers, this isn't something either the client, the resource server, or our OAuth service
# needs to know. (Does this even work for federated ID providers that require MFA?)
class ResourceOwnerClientConfig(OidcAuthClientConfig):
    """
    Configuration required for [planet_auth.ResourceOwnerAuthClient][]
    """

    def __init__(self, username=None, password=None, **kwargs):
        super().__init__(**kwargs)
        if username:
            self._data["user_name"] = username
        if password:
            self._data["user_password"] = password

    def user_name(self) -> str:
        return self.lazy_get("user_name")

    def user_password(self) -> str:
        return self.lazy_get("user_password")

    # def check_data(self, data):
    #     super().check_data(data)
    #     # Allow - we can prompt the user.
    #     if not (data.get("user_name") and data.get("user_password)):
    #         raise AuthClientConfigException(message="username and password are both required for resource owner client.")
    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_resource_owner",
            "auth_client_class": ResourceOwnerAuthClient,
            "display_name": "Resource Owner",
            "description": "OAuth2 Resource Owner Flow for a non-confidential client." " (Not recommended)",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class ResourceOwnerAuthClientException(AuthClientException):
    pass


class ResourceOwnerAuthClientBase(
    OidcAuthClientWithRefreshOrReloginOidcTokenRequestAuthenticator, OidcAuthClient, ABC
):
    def __init__(self, client_config: ResourceOwnerClientConfig):
        super().__init__(client_config)
        self._resource_owner_client_config = client_config

    def _oidc_flow_login(
        self,
        allow_open_browser: Optional[bool],
        allow_tty_prompt: Optional[bool],
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        extra: Optional[dict],
        username: Optional[str] = None,
        password: Optional[str] = None,
        **kwargs,
    ) -> FileBackedOidcCredential:
        if not username:
            if self._resource_owner_client_config.user_name():
                username = self._resource_owner_client_config.user_name()
            else:
                if allow_tty_prompt:
                    username = input("Email: ")
                else:
                    raise ResourceOwnerAuthClientException(
                        message="Username must be provided when performing non-interactive login"
                    )

        if not password:
            if self._resource_owner_client_config.user_password():
                password = self._resource_owner_client_config.user_password()
            else:
                if allow_tty_prompt:
                    password = getpass.getpass(prompt="Password: ")
                else:
                    raise ResourceOwnerAuthClientException(
                        message="Password must be provided when performing non-interactive login"
                    )

        return FileBackedOidcCredential(
            self.token_client().get_token_from_password(
                client_id=self._resource_owner_client_config.client_id(),
                username=username,
                password=password,
                requested_scopes=requested_scopes,
                requested_audiences=requested_audiences,
                auth_enricher=self._client_auth_enricher,
                extra=extra,
            )
        )

    def can_login_unattended(self) -> bool:
        return bool(self._resource_owner_client_config.user_password()) and bool(
            self._resource_owner_client_config.user_name()
        )


class ResourceOwnerAuthClient(ResourceOwnerAuthClientBase, OidcAuthClientWithNoneClientAuth):
    """
    AuthClient implementation that implements the OAuth password grant
    to obtain user tokens.  This implementation is for public
    clients that cannot maintain client confidentiality.
    """

    # The base and mix-ins pretty much do it all.


class ResourceOwnerWithClientSecretClientConfig(ResourceOwnerClientConfig, OidcAuthClientWithClientSecretClientConfig):
    """
    Configuration required for [planet_auth.ResourceOwnerWithClientSecretAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_resource_owner_secret",
            "auth_client_class": ResourceOwnerWithClientSecretAuthClient,
            "display_name": "Resource Owner (Client Secret)",
            "description": "OAuth2 Resource Owner Flow for a confidential client using a shared client secret for authentication."
            " (Not recommended)",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class ResourceOwnerWithClientSecretAuthClient(
    ResourceOwnerAuthClientBase, OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment
):
    """
    AuthClient implementation that implements the OAuth password grant
    to obtain user tokens.  This implementation is for confidential
    clients that use a client secret to protect the client confidentiality.
    """

    # The base and mix-ins pretty much do it all.
    def __init__(self, client_config: ResourceOwnerWithClientSecretClientConfig):
        super().__init__(client_config)


class ResourceOwnerWithPubKeyClientConfig(ResourceOwnerClientConfig, OidcAuthClientWithPubKeyClientConfig):
    """
    Configuration required for [planet_auth.ResourceOwnerWithPubKeyAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_resource_owner_pubkey",
            "auth_client_class": ResourceOwnerWithPubKeyAuthClient,
            "display_name": "Resource Owner (Public Key)",
            "description": "OAuth2 Resource Owner Flow for a confidential client using public key authentication."
            " (Not recommended)",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class ResourceOwnerWithPubKeyAuthClient(ResourceOwnerAuthClientBase, OidcAuthClientWithClientPubkey):
    """
    AuthClient implementation that implements the OAuth password grant
    to obtain user tokens.  This implementation is for confidential
    clients that use a public/private keypair ti protect the client confidentiality.
    """

    # The base and mix-ins pretty much do it all.
    def __init__(self, client_config: ResourceOwnerWithPubKeyClientConfig):
        super().__init__(client_config)
