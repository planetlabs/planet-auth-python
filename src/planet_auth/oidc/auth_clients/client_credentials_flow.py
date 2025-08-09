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

from abc import ABC
from typing import List, Optional

from planet_auth.oidc.api_clients.api_client import EnricherPayloadType, EnricherReturnType
from planet_auth.oidc.api_clients.oidc_request_auth import (
    prepare_client_secret_auth_payload,
)
from planet_auth.oidc.auth_client import (
    OidcAuthClient,
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


class ClientCredentialsClientSecretClientConfig(OidcAuthClientWithClientSecretClientConfig):
    """
    Configuration required for [planet_auth.ClientCredentialsClientSecretAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_client_credentials_secret",
            "auth_client_class": ClientCredentialsClientSecretAuthClient,
            "display_name": "Client Credentials (Client Secret)",
            "description": "OAuth2 Client Credentials Flow using a shared client secret for authentication.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class ClientCredentialsAuthClientBase(
    OidcAuthClientWithRefreshOrReloginOidcTokenRequestAuthenticator, OidcAuthClient, ABC
):
    def can_login_unattended(self) -> bool:
        # A valid config should always have everything we need.
        # What exactly that is will vary between the client auth methods.
        return True


class ClientCredentialsClientSecretAuthClient(
    ClientCredentialsAuthClientBase, OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment
):
    """
    AuthClient implementation that implements the OAuth client credentials grant
    to obtain tokens for the client itself.  This implementation is for confidential
    clients that use a client secret to protect the client confidentiality.
    """

    def __init__(self, client_config: ClientCredentialsClientSecretClientConfig):
        super().__init__(client_config)
        self._ccauth_client_config = client_config

    # With client credentials and a simple client secret, the auth server
    # insists that we put the secret in the payload during the initial
    # token request.  For other commands (e.g. token validate) it permits
    # us to send it an an auth header.  We prefer this as the default since
    # an auth header should be less likely to land in a log than URL
    # parameters or request payloads.
    def _client_auth_enricher_login(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        auth_payload = prepare_client_secret_auth_payload(
            client_id=self._oidc_client_secret_client_config.client_id(),
            client_secret=self._oidc_client_secret_client_config.client_secret(),
        )
        enriched_payload = {**raw_payload, **auth_payload}
        return enriched_payload, None

    def _oidc_flow_login(
        self,
        allow_open_browser: Optional[bool],
        allow_tty_prompt: Optional[bool],
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        extra: Optional[dict],
        **kwargs,
    ) -> FileBackedOidcCredential:
        self._warn_password_kwarg(**kwargs)
        self._warn_ignored_kwargs(["username", "password"], **kwargs)
        return FileBackedOidcCredential(
            self.token_client().get_token_from_client_credentials(
                client_id=self._ccauth_client_config.client_id(),
                requested_scopes=requested_scopes,
                requested_audiences=requested_audiences,
                auth_enricher=self._client_auth_enricher_login,
                extra=extra,
            )
        )


class ClientCredentialsPubKeyClientConfig(OidcAuthClientWithPubKeyClientConfig):
    """
    Configuration required for [planet_auth.ClientCredentialsPubKeyAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_client_credentials_pubkey",
            "auth_client_class": ClientCredentialsPubKeyAuthClient,
            "display_name": "Client Credentials (Public Key)",
            "description": "OAuth2 Client Credentials Flow using public key client authentication.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class ClientCredentialsPubKeyAuthClient(ClientCredentialsAuthClientBase, OidcAuthClientWithClientPubkey):
    """
    AuthClient implementation that implements the OAuth client credentials grant
    to obtain tokens for the client itself.  This implementation is for confidential
    clients that use a public/private keypair to protect the client confidentiality.
    """

    def __init__(self, client_config: ClientCredentialsPubKeyClientConfig):
        super().__init__(client_config)
        self._pubkey_client_config = client_config

    def _oidc_flow_login(
        self,
        allow_open_browser: Optional[bool],
        allow_tty_prompt: Optional[bool],
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        extra: Optional[dict],
        **kwargs,
    ):
        self._warn_password_kwarg(**kwargs)
        self._warn_ignored_kwargs(["username", "password"], **kwargs)
        return FileBackedOidcCredential(
            self.token_client().get_token_from_client_credentials(
                client_id=self._pubkey_client_config.client_id(),
                requested_scopes=requested_scopes,
                requested_audiences=requested_audiences,
                auth_enricher=self._client_auth_enricher,
                extra=extra,
            )
        )
