# Copyright 2024 Planet Labs PBC.
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

from abc import abstractmethod, ABC
from requests.auth import AuthBase
from typing import List, Optional, Tuple

from planet_auth.auth_client import AuthClientConfig, AuthClient, AuthClientConfigException, AuthClientException
from planet_auth.oidc.api_clients.authorization_api_client import AuthorizationApiClient
from planet_auth.oidc.api_clients.device_authorization_api_client import DeviceAuthorizationApiClient
from planet_auth.oidc.api_clients.discovery_api_client import DiscoveryApiClient
from planet_auth.oidc.api_clients.introspect_api_client import IntrospectionApiClient
from planet_auth.oidc.api_clients.jwks_api_client import JwksApiClient
from planet_auth.oidc.api_clients.oidc_request_auth import prepare_client_noauth_auth_payload
from planet_auth.oidc.token_validator import TokenValidator
from planet_auth.oidc.api_clients.revocation_api_client import RevocationApiClient
from planet_auth.oidc.api_clients.userinfo_api_client import UserinfoApiClient
from planet_auth.oidc.api_clients.token_api_client import TokenApiClient
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential


class OidcAuthClientConfig(AuthClientConfig, ABC):
    """
    Base config class shared by all OAuth/OIDC auth clients.
    """

    def __init__(
        self,
        auth_server: str = None,
        client_id: str = None,
        audiences: List[str] = None,
        scopes: List[str] = None,
        organization: str = None,  # Auth0 extension
        project_id: str = None,  # Planet Labs extension
        issuer: str = None,
        authorization_endpoint: str = None,
        device_authorization_endpoint: str = None,
        introspection_endpoint: str = None,
        jwks_endpoint: str = None,
        revocation_endpoint: str = None,
        userinfo_endpoint: str = None,
        token_endpoint: str = None,
        authorization_callback_acknowledgement: str = None,
        authorization_callback_acknowledgement_file: str = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._data["auth_server"] = auth_server
        self._data["authorization_callback_acknowledgement"] = authorization_callback_acknowledgement
        self._data["authorization_callback_acknowledgement_file"] = authorization_callback_acknowledgement_file
        self._data["client_id"] = client_id
        self._data["scopes"] = scopes
        self._data["audiences"] = audiences
        self._data["organization"] = organization
        self._data["project_id"] = project_id
        self._data["issuer"] = issuer

        self._data["authorization_endpoint"] = authorization_endpoint
        self._data["device_authorization_endpoint"] = device_authorization_endpoint
        self._data["introspection_endpoint"] = introspection_endpoint
        self._data["jwks_endpoint"] = jwks_endpoint
        self._data["revocation_endpoint"] = revocation_endpoint
        self._data["userinfo_endpoint"] = userinfo_endpoint
        self._data["token_endpoint"] = token_endpoint

        # Loaded JIT. Not in the serialized self._data representation.
        self._authorization_callback_acknowledgement_data: Optional[str] = None

    def check_data(self, data):
        super().check_data(data)
        if not data.get("auth_server"):
            raise AuthClientConfigException(
                message="auth_server must be configured for {} auth client".format(self.__class__.__name__)
            )
        if not data.get("client_id"):
            raise AuthClientConfigException(
                message="client_id must be configured for {} auth client".format(self.__class__.__name__)
            )

        # Do we actually want this restriction in the auth client, or leave that as a local restriction
        # in the validator call, since that is the only place this is a problem?
        if data.get("audiences"):
            if not isinstance(data.get("audiences"), list):
                raise AuthClientConfigException(
                    message="audiences must be a list type for {} auth client.".format(self.__class__.__name__)
                )
            if len(data.get("audiences")) != 1:
                raise AuthClientConfigException(
                    message="while it is a list type, audiences is only permitted to have one value at this time for {} auth client.".format(
                        self.__class__.__name__
                    )
                )

    def auth_server(self) -> str:
        return self.lazy_get("auth_server")

    def authorization_callback_acknowledgement(self) -> str:
        return self.lazy_get("authorization_callback_acknowledgement")

    def authorization_callback_acknowledgement_data(self) -> Optional[str]:
        # TODO: handle key refresh if the file has changed?
        self._lazy_load_authorization_callback_acknowledgement()
        return self._authorization_callback_acknowledgement_data

    def authorization_callback_acknowledgement_file(self) -> str:
        return self.lazy_get("authorization_callback_acknowledgement_file")

    def client_id(self) -> str:
        return self.lazy_get("client_id")

    def scopes(self) -> List[str]:
        return self.lazy_get("scopes")

    def audiences(self) -> List[str]:
        return self.lazy_get("audiences")

    def organization(self) -> str:
        return self.lazy_get("organization")

    def project_id(self) -> str:
        return self.lazy_get("project_id")

    def issuer(self) -> str:
        return self.lazy_get("issuer")

    def authorization_endpoint(self) -> str:
        return self.lazy_get("authorization_endpoint")

    def device_authorization_endpoint(self) -> str:
        return self.lazy_get("device_authorization_endpoint")

    def introspection_endpoint(self) -> str:
        return self.lazy_get("introspection_endpoint")

    def jwks_endpoint(self) -> str:
        return self.lazy_get("jwks_endpoint")

    def revocation_endpoint(self) -> str:
        return self.lazy_get("revocation_endpoint")

    def userinfo_endpoint(self) -> str:
        return self.lazy_get("userinfo_endpoint")

    def token_endpoint(self) -> str:
        return self.lazy_get("token_endpoint")

    def _lazy_load_authorization_callback_acknowledgement(self):
        # TODO: handle refresh if the file has changed?
        if not self._authorization_callback_acknowledgement_data:
            if self.authorization_callback_acknowledgement():
                self._authorization_callback_acknowledgement_data = self.authorization_callback_acknowledgement()
            else:
                ack_file_path = self.authorization_callback_acknowledgement_file()
                if ack_file_path:
                    with open(ack_file_path, mode="r", encoding="UTF-8") as ack_file:
                        self._authorization_callback_acknowledgement_data = ack_file.read()
        ## Nope.  The lower level libs have a fallback built-in default. "None" is valid here.
        # if not self._authorization_callback_acknowledgement_data:
        #    raise AuthClientConfigException(
        #        message="Authorization callback acknowledgement must be configured for auth client."
        #    )

    @classmethod
    def meta(cls):
        return {
            "config_hints": [
                {
                    "config_key": "auth_server",
                    "config_key_name": "Authorization Server",
                    "config_key_description": "Base URL for the OAuth2/OIDC authorization server",
                    # FIXME: This was planet_auth_config.Production.PRIMARY_PUBLIC_OAUTH_AUTHORITY.get("auth_server"),
                    #        but with knowledge of environments being pulled out of the core library we lost
                    #        that friendly default.  This is really only a concern for downstream applications,
                    #        like the CLI utility.
                    # "config_key_default": "auth server URL",
                },
                {
                    "config_key": "client_id",
                    "config_key_name": "Client ID",
                    "config_key_description": "Unique ID assigned to the client",
                },
            ]
        }


class OidcAuthClient(AuthClient, ABC):
    """
    Base class for AuthClient implementations that implement an OAuth/OIDC
    authentication flow.
    """

    def __init__(self, oidc_client_config: OidcAuthClientConfig):
        super().__init__(oidc_client_config)
        self._oidc_client_config = oidc_client_config
        self.__discovery_client = DiscoveryApiClient(auth_server=self._oidc_client_config.auth_server())
        self.__token_client = None
        self.__authorization_client = None
        self.__device_authorization_client = None
        self.__introspection_client = None
        self.__revocation_client = None
        self.__userinfo_client = None
        self.__jwks_client = None
        self.__token_validator = None
        self.__issuer = None
        # FIXME: Need authorization_acknowledgement_body here or from OidcAuthClientConfig
        #        This is something that belongs to the client more than the library.
        #        It's also something that's only relevant in a narrow set of circumstances:
        #        An auth code client that is locally listening for and responding
        #        to a redirect callback from the OAuth authorization endpoint.

    def _discovery(self):
        # We know the internals of the discovery client fetch this
        # JIT and caches
        # TODO: this does OIDC discovery.  Should we fall back to OAuth2
        #  discovery?  This comes down to .well-known/openid-configuration
        #  vs .well-known/oauth-authorization-server
        return self.__discovery_client.discovery()

    def _issuer(self):
        # Issuer is normally expected to be the same as the auth server.
        # we handle them separately to allow discovery under the auth
        # server url to set the issuer string value used in validation.
        # I can't see much use for this other than deployments where
        # proxy redirects may be in play. In such cases, a proxy may own
        # a public "auth server" URL that routes to particular instances,
        # and there is an expectation that "issuer" (used for token
        # validation) may deviate from the URL used to locate the auth server.
        if not self.__issuer:
            if self._oidc_client_config.issuer():
                self.__issuer = self._oidc_client_config.issuer()
            else:
                self.__issuer = self._discovery()["issuer"]
                # TODO: should we fall back to the "auth server" if
                #  discovery fails?  In the wild we've seen oauth servers
                #  that lack discovery endpoints, and it would be bad
                #  user experience to force users to provide both
                #  an auth server and an issuer.
        return self.__issuer

    def _token_validator(self):
        if not self.__token_validator:
            self.__token_validator = TokenValidator(self.jwks_client())
        return self.__token_validator

    def authorization_client(self):
        if not self.__authorization_client:
            if self._oidc_client_config.authorization_endpoint():
                auth_endpoint = self._oidc_client_config.authorization_endpoint()
            else:
                auth_endpoint = self._discovery().get("authorization_endpoint")
            if not auth_endpoint:
                raise AuthClientException(
                    message="Authorization endpoint is not available for the current authorization server"
                )
            self.__authorization_client = AuthorizationApiClient(
                authorization_uri=auth_endpoint,
                authorization_callback_acknowledgement_response_body=self._oidc_client_config.authorization_callback_acknowledgement_data(),
            )
        return self.__authorization_client

    def device_authorization_client(self):
        if not self.__device_authorization_client:
            if self._oidc_client_config.device_authorization_endpoint():
                device_auth_endpoint = self._oidc_client_config.device_authorization_endpoint()
            else:
                device_auth_endpoint = self._discovery()["device_authorization_endpoint"]
            self.__device_authorization_client = DeviceAuthorizationApiClient(
                device_authorization_uri=device_auth_endpoint
            )
        return self.__device_authorization_client

    def introspection_client(self):
        if not self.__introspection_client:
            if self._oidc_client_config.introspection_endpoint():
                introspection_endpoint = self._oidc_client_config.introspection_endpoint()
            else:
                introspection_endpoint = self._discovery().get("introspection_endpoint")
            if not introspection_endpoint:
                raise AuthClientException(
                    message="Token introspection endpoint is not available for the current authorization server"
                )
            self.__introspection_client = IntrospectionApiClient(introspection_endpoint)
        return self.__introspection_client

    def jwks_client(self):
        if not self.__jwks_client:
            if self._oidc_client_config.jwks_endpoint():
                jwks_endpoint = self._oidc_client_config.jwks_endpoint()
            else:
                jwks_endpoint = self._discovery().get("jwks_uri")
            if not jwks_endpoint:
                raise AuthClientException(
                    message="JWKS endpoint is not available for the current authorization server"
                )
            self.__jwks_client = JwksApiClient(jwks_endpoint)
        return self.__jwks_client

    def revocation_client(self):
        if not self.__revocation_client:
            if self._oidc_client_config.revocation_endpoint():
                revocation_endpoint = self._oidc_client_config.revocation_endpoint()
            else:
                revocation_endpoint = self._discovery().get("revocation_endpoint")
            if not revocation_endpoint:
                raise AuthClientException(
                    message="Token revocation endpoint is not available for the current authorization server"
                )
            self.__revocation_client = RevocationApiClient(revocation_endpoint)
        return self.__revocation_client

    def userinfo_client(self):
        if not self.__userinfo_client:
            if self._oidc_client_config.userinfo_endpoint():
                userinfo_endpoint = self._oidc_client_config.userinfo_endpoint()
            else:
                userinfo_endpoint = self._discovery().get("userinfo_endpoint")
            if not userinfo_endpoint:
                raise AuthClientException(
                    message="User information endpoint is not available for the current authorization server"
                )
            self.__userinfo_client = UserinfoApiClient(userinfo_endpoint)
        return self.__userinfo_client

    def token_client(self):
        if not self.__token_client:
            if self._oidc_client_config.token_endpoint():
                token_endpoint = self._oidc_client_config.token_endpoint()
            else:
                token_endpoint = self._discovery().get("token_endpoint")
            if not token_endpoint:
                raise AuthClientException(
                    message="Token endpoint is not available for the current authorization server"
                )
            self.__token_client = TokenApiClient(token_endpoint)
        return self.__token_client

    # Note: I don't really like that auth_client knows about the HTTP-ness,
    #       that's the job of the API client classes to abstract.  It's
    #       difficult to entirely separate these concerns, since the high
    #       level concept of "OIDC client type" imposes itself on some of
    #       the low level protocol interactions.
    @abstractmethod
    def _client_auth_enricher(self, raw_payload: dict, audience: str) -> Tuple[dict, Optional[AuthBase]]:
        """
        Some OIDC endpoints require client auth, and how auth is done can
        vary depending on how the OIDC provider is configured to handle the
        particular client and the particular flow of the token grant.

        Auth clients implementation classes must implement a method to enrich
        requests with appropriate authentication either by modifying the
        payload, or providing an AuthBase for the request, which will be used
        where needed before sending requests to the authorization servers.

        If no enrichment is needed or appropriate, implementations should
        return the raw payload unmodified, and None for the AuthBase.

        See
        https://developer.okta.com/docs/reference/api/oidc/#client-authentication-methods
        """

    def _apply_config_fallback(self, requested_scopes, requested_audiences, extra):
        if not requested_scopes:
            requested_scopes = self._oidc_client_config.scopes()

        if not requested_audiences:
            requested_audiences = self._oidc_client_config.audiences()

        if not extra:
            extra = {}
        if not extra.get("organization"):
            if self._oidc_client_config.organization():
                extra["organization"] = self._oidc_client_config.organization()
        if not extra.get("project_id"):
            if self._oidc_client_config.project_id():
                extra["project_id"] = self._oidc_client_config.project_id()

        return requested_scopes, requested_audiences, extra

    def login(
        self,
        allow_open_browser: Optional[bool] = False,
        allow_tty_prompt: Optional[bool] = False,
        requested_scopes: Optional[List[str]] = None,
        requested_audiences: Optional[List[str]] = None,
        extra: Optional[dict] = None,
        **kwargs,
    ):
        """
        Obtain tokens from the OIDC auth server using an appropriate login
        flow. The base implementation here handles common config fallback
        behaviors. Concrete subclasses must implement the flow specific logic
        in a _oidc_flow_login() method.
        Args:
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
        final_requested_scopes, final_requested_audiences, final_extra = self._apply_config_fallback(
            requested_scopes=requested_scopes, requested_audiences=requested_audiences, extra=extra
        )

        return self._oidc_flow_login(
            allow_open_browser=allow_open_browser,
            allow_tty_prompt=allow_tty_prompt,
            requested_scopes=final_requested_scopes,
            requested_audiences=final_requested_audiences,
            extra=final_extra,
            **kwargs,
        )

    @abstractmethod
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
        Abstract method that concrete subclasses must implement
        to complete the login flow and return a valid OIDC Credential.
        """

    def refresh(
        self, refresh_token: str, requested_scopes: List[str] = None, extra: Optional[dict] = None
    ) -> FileBackedOidcCredential:
        """
        Refresh auth tokens using the provided refresh token
        Args:
            refresh_token: the refresh token to use.
            requested_scopes: a list of strings specifying the scopes to
                request during the token refresh. If not specified, server
                default behavior will apply.
            extra: a dict extra data to pass to the authorization server.
        Returns:
            A FileBackedOidcCredential object
        """
        # Disabled scope fallback for now.
        # The client config default may have more than the user consented to,
        # which will result in a failure.  Introspection could be used, but
        # if this approach is taken, the access token should be inspected.
        # Inspecting refresh tokens shows its full power, whereas inspecting
        # the access token reveals if it was down-scoped for some reason.
        # However, access tokes live a short time, and inspection fails after
        # expiration, whereas refresh tokens may live much longer lives.
        #
        # if not requested_scopes:
        #    requested_scopes = self._oidc_client_config.scopes()

        # TODO: extra from config ??  Similar concerns as above.
        #  The general expectation is that an unadorned refresh
        #  "just works" as expected. It should not change what you have.

        return FileBackedOidcCredential(
            self.token_client().get_token_from_refresh(
                client_id=self._oidc_client_config.client_id(),
                refresh_token=refresh_token,
                requested_scopes=requested_scopes,
                auth_enricher=self._client_auth_enricher,
                extra=extra,
            )
        )

    def validate_access_token_remote(self, access_token: str) -> dict:
        """
        Validate the access token against the OIDC token introspection endpoint
        Parameters:
            access_token: The access token to validate
        Returns:
            The raw validate json payload
        """
        return self.introspection_client().validate_access_token(access_token, self._client_auth_enricher)

    def validate_access_token_local(
        self, access_token: str, required_audience: str = None, scopes_anyof: list = None
    ) -> dict:
        # Note:
        #     Tokens may have multiple audiences. When someone requests a
        #     token with multiple audiences, the expectation during login is
        #     that the result has multiple audiences.  However, the underlying
        #     behavior of the jwt.decode() validation appears to be satisfied
        #     if the token under validation has any one of the provided
        #     audiences.  It does not check that all of the provided
        #     audiences are present. Our expectation is aligned with
        #     the former: if multiple audiences are requested for validation,
        #     we insist that they are all present.
        #
        # WARNING:
        #     For the above reason, we are currently only accepting
        #     a single value for the required audience.  If you truly
        #     need to check that a token contains multiple audiences,
        #     you should make multiple calls to this method.
        #     Since a consumer should never really self identify as
        #     multiple audiences, and the same claim can mean different
        #     things to different audiences, this is considered expected
        #     behavior.
        if not required_audience:
            conf_audiences = self._oidc_client_config.audiences()
            if not conf_audiences:
                raise AuthClientException(
                    message="Required audience was not specified either in the auth client config, or provided as an argument to token validation."
                )
            if len(conf_audiences) != 1:
                raise AuthClientException(
                    message="When using the auth client config's audiences as the source for required token audience during validaiton, only one audience may be specified."
                )
            required_audience = conf_audiences[0]

        return self._token_validator().validate_token(
            token_str=access_token,
            issuer=self._issuer(),
            audience=required_audience,
            scopes_anyof=scopes_anyof,
        )

    def validate_id_token_remote(self, id_token: str) -> dict:
        """
        Validate the ID token against the OIDC token introspection endpoint
        Parameters:
            id_token: ID token to validate
        Returns:
            The raw validated json payload
        """
        return self.introspection_client().validate_id_token(id_token, self._client_auth_enricher)

    def validate_id_token_local(self, id_token: str) -> dict:
        """
        Validate the ID token locally. A remote connection may still be made
        to obtain signing keys.
        Parameters:
            id_token: ID token to validate
        Returns:
            Upon success, the validated token claims are returned
        """
        return self._token_validator().validate_id_token(
            token_str=id_token, issuer=self._issuer(), client_id=self._oidc_client_config.client_id()
        )

    def validate_refresh_token_remote(self, refresh_token: str) -> dict:
        """
        Validate the refresh token against the OIDC token introspection
        endpoint
        Parameters:
            refresh_token: Refresh token to validate
        Returns:
            The raw validate json payload
        """
        return self.introspection_client().validate_refresh_token(refresh_token, self._client_auth_enricher)

    def revoke_access_token(self, access_token: str) -> None:
        """
        Revoke the access token with the OIDC provider.
        Parameters:
            access_token: The access token to revoke
        """
        self.revocation_client().revoke_access_token(access_token, self._client_auth_enricher)

    def revoke_refresh_token(self, refresh_token: str) -> None:
        """
        Revoke the refresh token with the OIDC provider.
        Parameters:
            refresh_token: The refresh token to revoke
        """
        self.revocation_client().revoke_refresh_token(refresh_token, self._client_auth_enricher)

    def userinfo_from_access_token(self, access_token: str) -> dict:
        """
        Look up user information from the auth server using the access token.
        Parameters:
            access_token: User access token.
        """
        return self.userinfo_client().userinfo_from_access_token(access_token=access_token)

    def get_scopes(self) -> List[str]:
        """
        Query the authorization server for a list of scopes.
        Returns:
            Returns a list of scopes that may be requested during a call
                to login or refresh
        """
        return self._discovery()["scopes_supported"]


class OidcAuthClientWithNoneClientAuth(OidcAuthClient, ABC):
    """
    Mix-in base class for "public" (non-confidential) OAuth/OIDC auth clients.
    """

    def _client_auth_enricher(self, raw_payload: dict, audience: str) -> Tuple[dict, Optional[AuthBase]]:
        auth_payload = prepare_client_noauth_auth_payload(client_id=self._oidc_client_config.client_id())
        enriched_payload = {**raw_payload, **auth_payload}
        return enriched_payload, None