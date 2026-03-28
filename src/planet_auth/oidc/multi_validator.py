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

import jwt
from typing import Dict, List, NamedTuple, Optional, Tuple

import planet_auth.logging.auth_logger
from planet_auth import ExpiredTokenException, TokenValidatorException, InvalidArgumentException
from planet_auth.auth import Auth
from planet_auth.auth_client import AuthClient
from planet_auth.auth_exception import AuthException, InvalidTokenException
from planet_auth.logging.events import AuthEvent
from planet_auth.oidc.api_clients.introspect_api_client import IntrospectionApiClient
from planet_auth.oidc.auth_client import OidcAuthClient


class TrustEntry(NamedTuple):
    """An (issuer, audience) pair representing a trusted token authority."""

    issuer: str
    audience: str


auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class OidcMultiIssuerValidator:
    """
    The OidcMultiIssuerValidator is a token validator that can be configured
    to trust multiple token issuers. This is not expected to be a normal
    operating mode for most services. This was developed to support migration
    use cases.

    Trust is configured as a set of (issuer, audience) pairs. The same
    issuer may appear multiple times with different audiences, allowing
    a service to accept tokens from the same authorization server that
    were issued for different audiences.

    This is a higher level utility class, and is built on top of
    [planet_auth.AuthClient][] classes.  For a lower level utilities,
    see [planet_auth.TokenValidator][], or see the validation
    functionality built into [planet_auth.AuthClient][].

    Warning:
        Never ever ever EVER use this to bridge between trust environments.
        For example, do not use this to trust staging and production environment
        issuing authorities.
    """

    # TODO: Should we consider taking AuthClient rather than Auth type?
    #       We only ever use the client (but Auth is the more friendly
    #       higher level aggregation)
    #       The use case of validating incoming request doesn't really
    #       require the the outbound request authentication capabilities
    #       provided by the Auth type.
    # TODO: The lower level TokenValidtor allows the caller to specify
    #       what token signing algorithms are trusted.  This class does
    #       not. It's not exactly straight forward what changes to make
    #       since we don't use the Token Validator directly.  Rather,
    #       we work through the wrapper Auth and AuthClient types so
    #       that we have access to remote validators and possibly could
    #       handle opaque tokens where "algorithm" doesn't really apply.
    def __init__(
        self,
        trusted: List[Auth],
        log_result: bool = True,
    ):
        """
        Create a new multi issuer validator using the provided auth clients.
        The auth clients are expected to be any Auth that implements OIDC functionality.

        Trust is established as (issuer, audience) pairs.  Each provided Auth
        context must be configured with an audience.  The same issuer may
        appear multiple times as long as the audience differs, enabling
        services to accept tokens from one authorization server that were
        minted for different audiences.

        Parameters:
            trusted:
            log_result:
        """
        self._trusted: Dict[TrustEntry, Auth] = {}
        self._log_result = log_result

        def _check_auth_client(auth_client: AuthClient) -> OidcAuthClient:
            # pylint: disable=protected-access
            if not isinstance(auth_client, OidcAuthClient):
                raise AuthException(message="Auth Provider must be an OIDC auth provider type")
            if not auth_client._oidc_client_config.audiences():
                raise AuthException(
                    message="Auth Providers used for OIDC token validation must have the audiences configuration value set."
                )
            if len(auth_client._oidc_client_config.audiences()) > 1:
                raise AuthException(
                    message=(
                        "Each trusted auth provider must be configured with exactly one audience"
                        " when used for token validation. To trust multiple audiences from the"
                        " same issuer, provide separate entries for each (issuer, audience) pair."
                        " The 'audiences' configuration field is a list because the underlying"
                        " client configuration schema is shared with OAuth clients that request"
                        " tokens, where multiple audiences can be meaningful."
                    )
                )
            return auth_client

        for auth_provider in trusted:
            if auth_provider:
                auth_client = _check_auth_client(auth_provider.auth_client())
                issuer = auth_client._issuer()
                audience = auth_client._oidc_client_config.audiences()[0]
                trust_key = TrustEntry(issuer=issuer, audience=audience)
                if trust_key in self._trusted:
                    raise AuthException(
                        message="Cannot configure multiple auth providers for the same issuer '{}' and audience '{}'".format(
                            issuer, audience
                        )
                    )
                self._trusted[trust_key] = auth_provider

    # TODO: we should probably deprecate this method...
    @staticmethod
    def from_auth_server_urls(
        trusted_auth_server_urls: List[str],
        audience: str = None,
        log_result: bool = True,
    ):
        """
        Create a new multi issuer validator from the provided OAuth server URLs.
        This is a convenience method for common cases.

        Warning:
            When mutli validators are initialized from URLs by this method, it is
            assumed that the auth server URL (used to perform OIDC discovery and
            locate all the other API endpoints) and the issuer (which is burned
            into the signed access tokens) are the same. This is normally
            true, but not universally required. For example, some network
            proxy configurations may make these different.

            This assumption is made in part to avoid the discovery lookup
            during construction. Since a network lookup could potentially fail,
            construction of the entire configuration could be rendered non-functional
            by a network or configuration problem impacting a single auth server.

            The multi-validator requires foreknowledge of all the issuers for
            proper initialization. So, without this assumption, it would be unavoidable
            to introduce network risk into the constructor.  This assumption
            allows us to push all network errors to runtime, and avoids
            possible initialization time errors.
        """
        return OidcMultiIssuerValidator.from_issuer_audience_pairs(
            trusted=[TrustEntry(issuer=url, audience=audience) for url in trusted_auth_server_urls if url],
            log_result=log_result,
        )

    @staticmethod
    def from_issuer_audience_pairs(
        trusted: List["TrustEntry"],
        log_result: bool = True,
    ):
        """
        Create a new multi issuer validator from a list of
        [planet_auth.TrustEntry][] named tuples.  This is the simplest way
        to configure the multi-validator for local-only token validation,
        and makes the trust model explicit.

        Each entry represents a single trusted (issuer, audience) pair.
        The same issuer may appear multiple times with different audiences,
        enabling a service to accept tokens from one authorization server
        that were minted for different audiences.

        For advanced use cases that require remote token validation (e.g.
        revocation checks), use ``from_auth_server_configs`` instead, which
        allows specifying client credentials and other auth client
        configuration.

        Warning:
            This method assumes that the auth server URL and the issuer
            (as burned into signed access tokens) are the same.  This is
            normally true, but not universally required.  See
            ``from_auth_server_urls`` for a discussion of the implications.

        Parameters:
            trusted: A list of [planet_auth.TrustEntry][] named tuples.
                Each entry represents a single trusted authority.  Falsy
                entries are ignored.
            log_result: Control whether successful token validations should
                be logged.

        Example:
            ```python
            from planet_auth import OidcMultiIssuerValidator, TrustEntry

            auth_validator = OidcMultiIssuerValidator.from_issuer_audience_pairs(
                trusted=[
                    TrustEntry(issuer="https://oauth_server.example.com/oauth2/server_id", audience="https://api.example.com/"),
                    # Same issuer, different audience:
                    TrustEntry(issuer="https://oauth_server.example.com/oauth2/server_id", audience="https://internal-api.example.com/"),
                    # Different issuer:
                    TrustEntry(issuer="https://other-oauth.example.com/oauth2/server_id", audience="https://api.example.com/"),
                ],
            )
            ```
        """
        auth_providers = []
        for entry in trusted:
            if entry:
                if not entry.issuer or not entry.audience:
                    raise TypeError("TrustEntry must have non-empty issuer and audience values.")
                auth_providers.append(
                    Auth.initialize_from_config_dict(
                        client_config={
                            "client_type": "oidc_client_validator",
                            "auth_server": entry.issuer,
                            "issuer": entry.issuer,
                            "audiences": [entry.audience],
                        }
                    )
                )

        return OidcMultiIssuerValidator(
            trusted=auth_providers,
            log_result=log_result,
        )

    @staticmethod
    def from_auth_server_configs(
        trusted_auth_server_configs: List[dict],
        log_result: bool = True,
    ):
        """
        Create a new multi issuer validator from the provided auth client
        config dictionaries.

        Parameters:
            trusted_auth_server_configs: A list of configuration dictionaries.
                Unless remote validation is required, the configuration dictionaries
                may be sparse, containing only the `auth_server` and `audiences` properties.
                `auth_server` is expected to be a single string, containing the URL
                of the OAuth issuer.  `audiences` is expected to be an array containing
                a single audience string.  The same auth server may appear in multiple
                configuration entries with different audiences, enabling a service to
                accept tokens from one authorization server that were minted for
                different audiences.
            log_result: Control whether successful token validations against
                trusted auth servers should be logged.

        Example:
            ```python
            auth_validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
                trusted_auth_server_configs=[
                    {
                        "auth_server": "https://oauth_server.example.com/oauth2/auth_server_id",
                        "audiences": ["https://api.example.com/"],
                    },
                    # Same issuer, different audience:
                    {
                        "auth_server": "https://oauth_server.example.com/oauth2/auth_server_id",
                        "audiences": ["https://internal-api.example.com/"],
                    },
                ],
            )
            ```
        """
        trusted = []

        def _doctor_config(auth_server_conf):
            # patch up sparse configs.
            if not auth_server_conf.get("client_type"):
                auth_server_conf["client_type"] = "oidc_client_validator"
            if not auth_server_conf.get("issuer"):
                # Optimization. Might not be universally safe.  Short circuits
                # discovery and has all the implications discussed above.
                auth_server_conf["issuer"] = auth_server_conf.get("auth_server")

        for auth_server_conf in trusted_auth_server_configs:
            if auth_server_conf:
                _doctor_config(auth_server_conf)
                trusted.append(Auth.initialize_from_config_dict(client_config=auth_server_conf))

        return OidcMultiIssuerValidator(
            trusted=trusted,
            log_result=log_result,
        )

    @staticmethod
    def _check_access_token(
        token: str, auth_client: AuthClient, do_remote: bool, scopes_anyof: list = None
    ) -> Tuple[Dict, Optional[Dict]]:
        # The client MUST be configured with the expected audience for local validation
        local_validation = auth_client.validate_access_token_local(access_token=token, scopes_anyof=scopes_anyof)
        if not local_validation:
            # We expect the auth client to throw when the token cannot be validated.
            # Protect ourselves against misbehaving implementations.
            raise AuthException(message="Internal error. No claims could be validated, but no error was reported.")

        remote_validation = None
        if do_remote:
            remote_validation = auth_client.validate_access_token_remote(access_token=token)
            # This will raise on invalid results.
            # The OIDC implementations should already do this, but we double-check
            # so that MultiIssuerValidator can work with arbitrary
            # auth clients whose implementations we may not know.
            IntrospectionApiClient.check_introspection_response(remote_validation)

        return local_validation, remote_validation

    @staticmethod
    def _get_token_audiences(unverified_decoded_token: dict) -> List[str]:
        """
        Extract audiences from an unverified token.  Per the OIDC/OAuth2 spec,
        the ``aud`` claim may be a single string or a list of strings.
        Returns a list in either case, or an empty list when ``aud`` is absent.
        """
        aud = unverified_decoded_token.get("aud")
        if aud is None:
            return []
        if isinstance(aud, str):
            return [aud]
        if isinstance(aud, list):
            return [a for a in aud if isinstance(a, str)]
        return []

    def _select_validator(self, token) -> Auth:
        # WARNING: Treat unverified token claims like toxic waste.
        #          Nothing can be trusted until the token is verified.
        unverified_decoded_token = jwt.decode(token, options={"verify_signature": False})  # nosemgrep
        issuer = unverified_decoded_token.get("iss")
        if not issuer:
            # PyJWT does not seem to raise if the issuer is explicitly None, even when
            # verify_iss was selected.
            raise InvalidTokenException(message="Cannot validate token that does not include an issuer ('iss') claim")
        if not isinstance(issuer, str):
            raise InvalidTokenException(
                message=f"Issuer claim ('iss') must be a of string type. '{type(issuer).__name__}' type was detected."
            )

        token_audiences = self._get_token_audiences(unverified_decoded_token)
        for aud in token_audiences:
            validator = self._trusted.get(TrustEntry(issuer=issuer, audience=aud))
            if validator:
                return validator

        raise AuthException(
            message="Rejecting token from an unrecognized issuer/audience combination. issuer='{}' audiences={}".format(
                issuer, token_audiences
            ),
            event=AuthEvent.TOKEN_INVALID_BAD_ISSUER,
        )

    # TODO?: remote revocation should cache failures to protect auth
    #        from abuse.  We never expect invalid tokens to become valid.
    #        (Should this be a concern of the inner validators, or this higher class?)
    # TODO: add required_claims_TODO or the like?  Need to nail down
    #       the exact contract this lib provides.  AuthN vs AuthZ.
    #       As of now, we are drawing the line as scope claims.
    @auth_logger.log_exception(default_event=AuthEvent.TOKEN_INVALID, exception_cls=InvalidTokenException)
    @TokenValidatorException.recast(jwt.PyJWTError)
    @InvalidTokenException.recast(jwt.InvalidTokenError)
    @ExpiredTokenException.recast(jwt.ExpiredSignatureError)
    def validate_access_token(
        self, token: str, do_remote_revocation_check: bool = False, scopes_anyof: list = None
    ) -> Tuple[Dict, Optional[Dict]]:
        """
        Validate an access token, and return the token's claims if the
        all validation has succeeded.

        Remote revocation checks should be done for high value operations
        where it is undesirable to allow revoked tokens to be used
        for the remainder of their lifetime.  Token lifetimes
        should be chosen to be an acceptable trade-off between
        permitting revoked tokens for the remainder of the token lifespan
        for performance and scalability, and performing remote validation
        for extra security.

        When an invalid token is presented, an exception is thrown.

        Parameters:
            token: Token to validate
            do_remote_revocation_check: Control whether the issuer will be
                consulted for revocation of the access token.
            scopes_anyof: Optional list of OAuth2 scopes to check for in the token.
                This list is an "any of" list of scopes. As long as one of the scopes in the
                list is present, validation will pass. If none of the scopes are present,
                validation will fail.
        Returns:
            Returns a tuple of validation results, as returned from
                [planet_auth.AuthClient.validate_access_token_local][]
                and [planet_auth.AuthClient.validate_access_token_remote][]
        """

        if not token:
            raise InvalidArgumentException(message="Cannot decode empty string as a token")

        validator = self._select_validator(token)
        local_validation, remote_validation = self._check_access_token(
            token=token,
            auth_client=validator.auth_client(),
            do_remote=do_remote_revocation_check,
            scopes_anyof=scopes_anyof,
        )

        if self._log_result:
            auth_logger.info(
                msg="Accepting access token from a primary issuing authority",
                event=AuthEvent.TOKEN_VALID,
                # FIXME? - We do not currently pass this info up from the validators.
                # jwt_header_json={"alg": "RS256"},
                jwt_body_json=local_validation,
            )

        return local_validation, remote_validation
