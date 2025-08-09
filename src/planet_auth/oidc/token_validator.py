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
import time
from typing import Dict, List

import planet_auth.logging.auth_logger
from planet_auth.auth_exception import AuthException, InvalidTokenException
from planet_auth.logging.events import AuthEvent
from planet_auth.oidc.api_clients.jwks_api_client import JwksApiClient

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class TokenValidatorException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class InvalidArgumentException(TokenValidatorException):
    pass


class ExpiredTokenException(InvalidTokenException):
    def __init__(self, event: AuthEvent = AuthEvent.TOKEN_INVALID_EXPIRED, **kwargs):
        super().__init__(event=event, **kwargs)


class InvalidAlgorithmTokenException(InvalidTokenException):
    def __init__(self, event: AuthEvent = AuthEvent.TOKEN_INVALID_BAD_ALGORITHM, **kwargs):
        super().__init__(event=event, **kwargs)


class ScopeNotGrantedTokenException(InvalidTokenException):
    def __init__(self, event: AuthEvent = AuthEvent.TOKEN_INVALID_BAD_SCOPE, **kwargs):
        super().__init__(event=event, **kwargs)


class UnknownSigningKeyTokenException(InvalidTokenException):
    def __init__(self, event: AuthEvent = AuthEvent.TOKEN_INVALID_BAD_SIGNING_KEY, **kwargs):
        super().__init__(event=event, **kwargs)


_SCOPE_CLAIM_RFC8693 = "scope"  # See RFC 8693, 9068
_SCOPE_CLAIM_OKTA = "scp"  # Okta uses a different claim

DEFAULT_TRUSTED_ALGORITHMS = ["rs256"]


class TokenValidator:
    """
    Helper class to perform validation of OAuth2 JWT tokens.
    This class provides the implementation for the locally performed
    validation in [planet_auth.OidcAuthClient][] classes, but may
    also be used as a stand-alone validator.

    This is a lower level utility class, and has no dependency
    or knowledge of the higher level [planet_auth.AuthClient][]
    or [planet_auth.Auth][] classes.

    For a higher level application utility, see [planet_auth.OidcMultiIssuerValidator][]
    """

    # Keys really don't change often... Maybe quarterly. In all but
    # emergency situations a new key would be published long before the
    # old one is removed from circulation.  We throttle key fetches so we
    # don't degenerate into DOS'ing the JWKS endpoint if presented with
    # requests using tokens with invalid keys.  So, the default fetch
    # interval can be wide.
    # TODO: implement a max interval - need to push out removed keys.
    def __init__(self, jwks_client: JwksApiClient, min_jwks_fetch_interval=300, trusted_algorithms: List[str] = None):
        self._jwks_client = jwks_client
        self._keys_by_id: Dict[str, jwt.PyJWK] = {}
        self._load_time = 0
        self.min_jwks_fetch_interval = min_jwks_fetch_interval
        # TODO: Some guardrails?
        #       Mixing trust of symmetric and asymmetric key algorithms can be dangerous.
        #       This class is really only designed for asymmetric keys. You would not
        #       usually fetch symmetric keys from a jwks endpoint.
        self._trusted_algorithms = set()
        if not trusted_algorithms:
            self._trusted_algorithms.update(DEFAULT_TRUSTED_ALGORITHMS)
        else:
            for alg in trusted_algorithms:
                self._trusted_algorithms.add(alg.lower())

    def _update(self):
        # TODO: bootstrap from cached values? the concern is large
        #   worker pools on disposable nodes generating load on churn.
        jwks_keys = self._jwks_client.jwks_keys()
        new_keys_by_id = {}
        for json_key in jwks_keys:
            # new_keys_by_id[json_key['kid']] = json_key
            try:
                new_keys_by_id[json_key["kid"]] = jwt.PyJWK(jwk_data=json_key)
            except jwt.PyJWKError as pyjwke:
                auth_logger.debug(
                    msg="Error while loading key from JWKS endpoint. Any attempt to verify tokens signed with this key will fail. Error: {}".format(
                        str(pyjwke)
                    ),
                    exception=pyjwke,
                )

        self._keys_by_id = new_keys_by_id
        self._load_time = int(time.time())

    def get_signing_key_by_id(self, key_id):
        key = self._keys_by_id.get(key_id)
        if (not key) and ((self._load_time + self.min_jwks_fetch_interval) < int(time.time())):
            self._update()
            key = self._keys_by_id.get(key_id)
        if not key:
            raise UnknownSigningKeyTokenException(
                message="Could not find signing key for key ID {}".format(key_id),
            )

        return key

    def _get_trusted_algorithm(self, unverified_header):
        # TODO - Can I just remove this and lean on jwt.decode(algorithms=[]) ??
        algorithm = unverified_header.get("alg")
        # Don't trust straight pass-through, since "none" is a valid
        # algorithm. Only trust specific algorithms.
        if not (algorithm and (algorithm.lower() in self._trusted_algorithms)):
            raise InvalidAlgorithmTokenException(message="Unknown or unsupported token algorithm {}".format(algorithm))

        return algorithm

    @TokenValidatorException.recast(jwt.PyJWTError)
    @InvalidTokenException.recast(jwt.InvalidTokenError)
    @ExpiredTokenException.recast(jwt.ExpiredSignatureError)
    def validate_token(
        self,
        token_str: str,
        issuer: str,
        audience: str,
        required_claims: list = None,
        scopes_anyof: list = None,
        nonce: str = None,
    ):
        """
        Validate the provided token string.  Required claims are validated
        for their presence only. It is up to the application to assert
        that the claim values meet thr requirements of the caller's use case.

        If a nonce is provided, the validator will require that the token
        have a nonce claim, and that its value matches the supplied value.

        Parameters:
            token_str: Raw encoded JWT string.
            issuer: Required token issuer.
            audience: Required token audience.
            required_claims: Optional list of additional claims that must be present in the token.
                these claims are only checked for the presence. It is up to the caller to assert
                that the values are appropriate for the application
            scopes_anyof: Optional list of OAuth2 scopes to check for in the token.
                This list is an "any of" list of scopes. As long as one of the scopes in the
                list is present, validation will pass. If none of the scopes are present,
                validation will fail.
            nonce: Optional nonce value to check for in the token.

        Note: A note on scope validation.
              "Any of" scope enforcement semantics may not make sense for all applications.
              "All of" is a feature that might be desirable, but has not been implemented.
              ("Any of" or "all of" for any other arbitrary claim might also have value. But again,
              this is not implemented here. At some point deriving application meaning from the
              claims present is a concern of the higher level application, and not a concern
              of the token validator.)
        """
        # PyJWT should enforce this, but we have unit tests in case...
        if not token_str:
            raise InvalidArgumentException(message="Cannot validate empty string as a token")
        if not issuer:
            # PyJWT does not seem to raise if the issuer is explicitly None, even when
            # verify_iss was selected.
            raise InvalidArgumentException(message="Cannot validate token with no required issuer provided")
        if not audience:
            raise InvalidArgumentException(message="Cannot validate token with no required audience provided")

        unverified_header = jwt.get_unverified_header(token_str)
        trusted_token_algorithm = self._get_trusted_algorithm(unverified_header)
        key_id = unverified_header.get("kid")
        signing_key = self.get_signing_key_by_id(key_id)
        validation_required_claims = ["aud", "exp", "iss"]
        if required_claims:
            validation_required_claims.extend(required_claims)
        if nonce:
            validation_required_claims.append("nonce")
        validated_claims = jwt.decode(  # Throws when invalid.
            token_str,
            signing_key.key,
            algorithms=[trusted_token_algorithm],
            issuer=issuer,
            audience=audience,
            options={
                "require": validation_required_claims,
                "verify_aud": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_signature": True,
            },
        )
        if nonce:
            if nonce != validated_claims.get("nonce"):
                raise InvalidTokenException(
                    message="Token nonce did not match expected value",
                    jwt_body=validated_claims,
                    event=AuthEvent.TOKEN_INVALID_BAD_NONCE,
                )

        # We check and throw the more specific errors around scope deliberately last.
        # Invalid tokens never get this far.  To get this far, all the basics of authentication
        # have been passed, and it's a question of the proper grants not having been given.
        if scopes_anyof:
            if validated_claims.get(_SCOPE_CLAIM_RFC8693):
                # RFC 8693 places scopes in a space delimited string.
                token_scopes = validated_claims.get(_SCOPE_CLAIM_RFC8693).split()
            elif validated_claims.get(_SCOPE_CLAIM_OKTA):
                # No split.  Okta places a list of strings in the token.
                token_scopes = validated_claims.get(_SCOPE_CLAIM_OKTA)
            else:
                raise InvalidTokenException(
                    message="No OAuth2 Scopes claim could be found in the access token",
                    jwt_body=validated_claims,
                    event=AuthEvent.TOKEN_INVALID_BAD_SCOPE,
                )

            if not list(set(scopes_anyof) & set(token_scopes)):
                raise ScopeNotGrantedTokenException(
                    message="Access token did not grant sufficient scope. One of [{}] required, but [{}] was granted".format(
                        ", ".join(scopes_anyof), ", ".join(token_scopes)
                    ),
                    jwt_body=validated_claims,
                    event=AuthEvent.TOKEN_INVALID_BAD_SCOPE,
                )

        if not validated_claims:
            # If we got here, jwt.decode passed, and we should at a minimum
            # have claims for audience and issuer.
            raise TokenValidatorException(
                message="No claims could be validated, but no error was detected. This should never happen.",
                event=AuthEvent.TRACE,
            )

        return validated_claims

    @staticmethod
    def hazmat_unverified_decode(token_str):
        # WARNING: Treat unverified token claims like toxic waste.
        #          Nothing can be trusted until the token is verified.
        unverified_complete = jwt.decode_complete(token_str, options={"verify_signature": False})  # nosemgrep
        return unverified_complete["header"], unverified_complete["payload"], unverified_complete["signature"]

    # TODO: should we error if the token has a nonce, and none was given to
    #       verify?
    def validate_id_token(self, token_str, issuer, client_id, required_claims=None, nonce=None):
        """
        Validate a JWT this is a OIDC ID token. Steps over and
        above basic token validation are performed, as described in
        https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        """
        validated_claims = self.validate_token(
            token_str=token_str, issuer=issuer, audience=client_id, required_claims=required_claims, nonce=nonce
        )

        # If the aud contains multiple values, azp must be present.
        validated_azp = None
        if isinstance(validated_claims.get("aud"), list):
            validated_azp = validated_claims.get("azp")
            if not validated_azp:
                raise InvalidTokenException(
                    message='"azp" claim mut be present when ID token contains' " multiple audiences."
                )

        # if the azp claim is present, it must equal the client ID.
        if validated_azp:
            if validated_azp != client_id:
                raise InvalidTokenException(
                    message='ID token "azp" claim expected to match the client'
                    ' ID "{}", but was "{}"'.format(client_id, validated_azp)
                )

        return validated_claims
