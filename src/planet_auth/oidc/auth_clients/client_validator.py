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
from typing import List, Optional, Union

from planet_auth import CredentialRequestAuthenticator
from planet_auth.auth_client import AuthClientException
from planet_auth.credential import Credential
from planet_auth.oidc.auth_client import OidcAuthClientConfig, OidcAuthClient, FileBackedOidcCredential
from planet_auth.oidc.api_clients.api_client import EnricherPayloadType, EnricherReturnType
from planet_auth.request_authenticator import ForbiddenRequestAuthenticator


class OidcClientValidatorAuthClientConfig(OidcAuthClientConfig):
    """
    Configuration for a [planet_auth.OidcClientValidatorAuthClient][] AuthClient
    """

    INTERNAL_CLIENT_ID = "__OidcClientValidatorAuthClientConfig__"

    def __init__(self, **kwargs):
        if not "client_id" in kwargs:
            # Note: This is partly wrong.  This can work for local only
            #       validation, but for remote validation you usually need
            #       to auth and have a client ID. Rename this "local validator"?
            # Client ID is required in the base class, and pretty much all Oidc clients,
            # but we don't really have a need for it, since this AuthClient
            # class exists largely to paint a AuthClient veneer on the downloading
            # of JWKS pub keys and doing JWT validation.
            kwargs["client_id"] = self.INTERNAL_CLIENT_ID
        super().__init__(**kwargs)

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_client_validator",
            "auth_client_class": OidcClientValidatorAuthClient,
            "display_name": "JWT Validator",
            "description": "Auth client that is only capable performing local validation of access tokens."
            " Cannot be used to make authenticated network calls.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class OidcClientValidatorAuthClient(OidcAuthClient):
    """
    The OidcClientValidatorAuthClient is an OAuth2/OIDC client that does
    not have an identity of its own. It cannot perform a login or obtain
    access or ID tokens, and it cannot call out to resource servers
    covered by the issuer's audiences on behalf of users or itself. Instead,
    this OAuth auth client type exists for programs that need to validate
    tokens than have been presented to them. This is useful for resource
    servers themselves when authenticating or authorizing clients.

    The implementation is essentially the [planet_auth.OidcAuthClient][]
    base class with outbound client capabilities disabled.

    It should be noted that the other [planet_auth.OidcAuthClient][]
    derived classes that implement various OAuth flows can also be
    used to validate clients when inbound and outbound connections
    fall under the same token issuer realm of trust.  But, for use
    cases where only the validation of incoming requests is required,
    this class is suitable and does not require the allocation of a
    client ID.
    """

    def __init__(self, client_config: OidcClientValidatorAuthClientConfig):
        super().__init__(client_config)
        # Not used at this time
        # self._client_validator_client_config = client_config

    def _client_auth_enricher(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        return raw_payload, None

    def _oidc_flow_login(
        self,
        allow_open_browser: Optional[bool] = False,
        allow_tty_prompt: Optional[bool] = False,
        requested_scopes: Optional[List[str]] = None,
        requested_audiences: Optional[List[str]] = None,
        extra: Optional[dict] = None,
        **kwargs,
    ) -> FileBackedOidcCredential:
        raise AuthClientException(message="OIDC Client Validator auth client cannot perform a login.")

    def refresh(
        self, refresh_token: str, requested_scopes: List[str] = None, extra: Optional[dict] = None
    ) -> FileBackedOidcCredential:
        raise AuthClientException(message="OIDC Client Validator auth client cannot refresh credentials.")

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> CredentialRequestAuthenticator:
        # return SimpleInMemoryRequestAuthenticator(token_body=None)  # Kinder and gentler failure.
        return ForbiddenRequestAuthenticator()

    def can_login_unattended(self) -> bool:
        return False
        # raise AuthClientException(message="OIDC Client Validator auth client cannot perform a login.")
