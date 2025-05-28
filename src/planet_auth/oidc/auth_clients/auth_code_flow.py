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

from planet_auth.auth_client import AuthClientConfigException, AuthClientException
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
    OidcAuthClientWithClientSecretClientConfig,
    OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment,
)
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.auth_client_default_authenticators import (
    OidcAuthClientWithRefreshingOidcTokenRequestAuthenticator,
)
from planet_auth.oidc.util import create_pkce_challenge_verifier_pair


class AuthCodeClientConfig(OidcAuthClientConfig):
    """
    Configuration required for [planet_auth.AuthCodeAuthClient][]
    """

    # TODO: simplify down to just one url, I think
    def __init__(self, redirect_uri: str = None, local_redirect_uri: str = None, **kwargs):
        super().__init__(**kwargs)
        # Redirect URI must match the client config on the OIDC service,
        # which may permit multiple values. We let our the config provide
        # different URLs for use cases where we either expect to configure a
        # redirect service locally, or expect it to be available remotely.
        # If only one is set, set both to the same value.
        if redirect_uri:
            self._data["redirect_uri"] = redirect_uri
        if local_redirect_uri:
            self._data["local_redirect_uri"] = local_redirect_uri

        if redirect_uri and not local_redirect_uri:
            self._data["local_redirect_uri"] = redirect_uri
        if local_redirect_uri and not redirect_uri:
            self._data["redirect_uri"] = local_redirect_uri

    def check_data(self, data):
        super().check_data(data)
        if not (data.get("redirect_uri") or data.get("local_redirect_uri")):
            raise AuthClientConfigException(
                message="A redirect_uri or local_redirect_uri is required for auth code client."
            )

    def local_redirect_uri(self) -> str:
        return self.lazy_get("local_redirect_uri")

    def redirect_uri(self) -> str:
        return self.lazy_get("redirect_uri")

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_auth_code",
            "auth_client_class": AuthCodeAuthClient,
            "display_name": "Auth Code",
            "description": "OAuth2 Auth Code with PKCE Flow for a non-confidential client.",
            "config_hints": super().meta().get("config_hints")
            + [
                {
                    "config_key": "redirect_uri",
                    "config_key_name": "Login redirect URL",
                    "config_key_description": "The callback URL used by the client to receive the results of authentication from the authorization server.",
                },
                {
                    "config_key": "local_redirect_uri",
                    "config_key_name": "Login redirect URL",
                    "config_key_description": "Alternative callback URL used by the client to receive the results of authentication from the authorization server.",
                },
            ],
        }


class AuthCodeAuthClientException(AuthClientException):
    pass


class AuthCodeAuthClientBase(OidcAuthClientWithRefreshingOidcTokenRequestAuthenticator, OidcAuthClient, ABC):
    def __init__(self, client_config: AuthCodeClientConfig):
        super().__init__(client_config)
        self._authcode_client_config = client_config

    def _oidc_flow_login(
        self,
        allow_open_browser: Optional[bool],
        allow_tty_prompt: Optional[bool],
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        extra: Optional[dict],
        **kwargs,
    ) -> FileBackedOidcCredential:
        """
        Obtain tokens from the OIDC auth server using the Auth Code OAuth
        flow with PKCE.  The Auth Code flow is inherently user interactive,
        and one of allow_tty_prompt or allow_open_browser must be true.

        Parameters:
            allow_open_browser: specify whether login is permitted to open
                a browser window.
            allow_tty_prompt: specify whether login is permitted to request
                input from the terminal.
            requested_scopes: a list of strings specifying the scopes to
                request.
            requested_audiences: a list of strings specifying the audiences
                to request.
            extra: a dict extra data to pass to the authorization server.
        Returns:
            A FileBackedOidcCredential object
        """

        self._warn_password_kwarg(**kwargs)
        self._warn_ignored_kwargs(["username", "password", "client_id", "client_secret"], **kwargs)

        pkce_code_verifier, pkce_code_challenge = create_pkce_challenge_verifier_pair()
        if allow_open_browser:
            redirect_uri = self._authcode_client_config.local_redirect_uri()
            authcode = self.authorization_client().authcode_from_pkce_auth_request_with_browser_and_callback_listener(
                client_id=self._authcode_client_config.client_id(),
                redirect_uri=redirect_uri,
                requested_scopes=requested_scopes,
                requested_audiences=requested_audiences,
                pkce_code_challenge=pkce_code_challenge,
                extra=extra,
            )
        elif allow_tty_prompt:
            redirect_uri = self._authcode_client_config.redirect_uri()
            authcode = self.authorization_client().authcode_from_pkce_auth_request_with_tty_input(
                client_id=self._authcode_client_config.client_id(),
                redirect_uri=redirect_uri,
                requested_scopes=requested_scopes,
                requested_audiences=requested_audiences,
                pkce_code_challenge=pkce_code_challenge,
                extra=extra,
            )
        else:
            raise AuthCodeAuthClientException(
                message="Both browser and terminal input disallowed.  No way to complete user login."
            )

        token_json = self.token_client().get_token_from_code(
            redirect_uri=redirect_uri,
            client_id=self._authcode_client_config.client_id(),
            code=authcode,
            code_verifier=pkce_code_verifier,
            auth_enricher=self._client_auth_enricher,
            # extra=extra,  # passed to Auth, not code redemption.
        )
        return FileBackedOidcCredential(token_json)

    def can_login_unattended(self) -> bool:
        # Always requires user interaction
        return False


class AuthCodeAuthClient(AuthCodeAuthClientBase, OidcAuthClientWithNoneClientAuth):
    """
    AuthClient implementation that implements the OAuth auth code grant with PKCE
    to obtain user tokens.  This implementation is for public clients that cannot
    maintain client confidentiality.
    """

    # The base and mix-ins pretty much do it all.


# client auth via secret or public/private keypair are optional for auth
# code flow clients. They are used when the client is "private"
class AuthCodeWithClientSecretClientConfig(AuthCodeClientConfig, OidcAuthClientWithClientSecretClientConfig):
    """
    Configuration required for [planet_auth.AuthCodeWithClientSecretAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_auth_code_secret",
            "auth_client_class": AuthCodeWithClientSecretAuthClient,
            "display_name": "Auth Code (Client Secret)",
            "description": "OAuth2 Auth Code with PKCE Flow for a confidential client using a shared client secret for authentication.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class AuthCodeWithClientSecretAuthClient(
    AuthCodeAuthClientBase, OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment
):
    """
    AuthClient implementation that implements the OAuth auth code grant with PKCE
    to obtain user tokens.  This implementation is for confidential
    clients that use a client secret to protect the client confidentiality.
    """

    # The base and mix-ins pretty much do it all.
    def __init__(self, client_config: AuthCodeWithClientSecretClientConfig):
        super().__init__(client_config)


class AuthCodeWithPubKeyClientConfig(AuthCodeClientConfig, OidcAuthClientWithPubKeyClientConfig):
    """
    Configuration required for [planet_auth.AuthCodeWithPubKeyAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_auth_code_pubkey",
            "auth_client_class": AuthCodeWithPubKeyAuthClient,
            "display_name": "Auth Code (Public Key)",
            "description": "OAuth2 Auth Code with PKCE Flow for a confidential client using public key authentication.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class AuthCodeWithPubKeyAuthClient(AuthCodeAuthClientBase, OidcAuthClientWithClientPubkey):
    """
    AuthClient implementation that implements the OAuth auth code grant with PKCE
    to obtain user tokens.  This implementation is for confidential
    clients that use a public/private keypair to protect the client confidentiality.
    """

    # The base and mix-ins pretty much do it all.
    def __init__(self, client_config: AuthCodeWithPubKeyClientConfig):
        super().__init__(client_config)
