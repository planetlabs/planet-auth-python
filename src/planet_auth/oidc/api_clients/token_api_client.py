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

import time
from typing import Dict, List, Optional

import planet_auth.logging.auth_logger
from planet_auth.oidc.api_clients.api_client import (
    OidcApiClient,
    OidcApiClientException,
    EnricherFuncType,
    _RequestParamsType,
)

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class TokenApiException(OidcApiClientException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class TokenApiTimeoutException(TokenApiException):
    pass


class TokenApiClient(OidcApiClient):
    """
    Low level API client for the OAuth Token endpoint. See
    RFC 6749 - The OAuth 2.0 Authorization Framework for protocol details.
    """

    def __init__(self, token_uri: str):
        """
        Create a new Token API Client.
        """
        super().__init__(endpoint_uri=token_uri)

    @staticmethod
    def _check_valid_token_response(json_response: Dict) -> None:
        if not json_response.get("expires_in"):
            # https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
            # Note: while OAuth requires the access_token field, and OIDC
            # built on top of oauth, it's addition of an ID token option
            # means that there might not be an access toke in a successful
            # response.
            #
            # 'expires_in' is only recommended in JWTs, not required, by the OAuth
            # spec. (But, I think it's required in the "token" response,
            # which is distinct from the JWT payload.)
            raise TokenApiException(message="Invalid token received. Missing expires_in field.")
            # auth_logger.warning(msg='Token response was missing expires_in field.')

    def _checked_call(
        self, token_params: _RequestParamsType, auth_enricher: Optional[EnricherFuncType] = None
    ) -> Dict:
        request_auth = None
        if auth_enricher:
            token_params, request_auth = auth_enricher(token_params, self._endpoint_uri)

        json_response = self._checked_post_json_response(token_params, request_auth)
        self._check_valid_token_response(json_response)
        return json_response

    def _polling_checked_call(
        self,
        token_params: _RequestParamsType,
        timeout: float,
        poll_interval: float,
        auth_enricher: Optional[EnricherFuncType] = None,
    ) -> Dict:
        start_time = time.time()
        while True:
            try:
                json_response = self._checked_call(token_params=token_params, auth_enricher=auth_enricher)
                return json_response
            except OidcApiClientException as oe:
                if oe.error_code == "authorization_pending":
                    pass
                elif oe.error_code == "slow_down":
                    poll_interval += 5  # See RFC 8628
                else:
                    raise oe
            now_time = time.time()
            if (now_time - start_time) < timeout:
                time.sleep(poll_interval)
            else:
                # We expect a expired_token error code, but the caller could
                # indicate they don't want to wait as long as the server is willing to.
                raise TokenApiTimeoutException(message="Timeout exceeded")

    def get_token_from_refresh(
        self,
        client_id: str,
        refresh_token: str,
        requested_scopes: List[str] = None,
        auth_enricher: Optional[EnricherFuncType] = None,
        extra: Dict = None,
    ) -> Dict:
        """
        Obtain tokens using a refresh token.

        Parameters:
            client_id: The ID of the OAuth client making the request.
            refresh_token: The refresh token to use.
            requested_scopes: A list of scopes to request when obtaining the
                refreshed tokens.  This list may only be a subset of the scopes
                that were initially granted to the client.  A scope increase may
                not be requested during refresh. A scope increase requires a new
                authorization (login).
            extra: Dict of extra parameters to pass to the token endpoint.

        Returns:
            Returns the token endpoint response payload upon success as a json
                object. If an error condition is detected, either from the HTTP
                layer or from a payload that indicates a failure, an exception
                will be raised.
        """
        if extra is None:
            extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        _extra = {k: v for k, v in extra.items() if v is not None}
        data = {
            **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            # Client id, secret, or assertion come from enricher.
            # 'client_id': client_id,
            # 'client_secret': client_secret
            # 'client_assertion_type':
            #        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            #  client_assertion': signed_jwt
        }
        if requested_scopes:
            # You can request down-scope on refresh, but the refresh token
            # remains potent.
            data["scope"] = " ".join(requested_scopes)

        return self._checked_call(data, auth_enricher)

    def get_token_from_client_credentials(
        self,
        client_id: str,
        requested_scopes: List[str] = None,
        requested_audiences: List[str] = None,
        auth_enricher: Optional[EnricherFuncType] = None,
        extra: Dict = None,
    ) -> Dict:
        """
        Obtain tokens using client credentials and the client credentials grant
        OAuth flow.

        Parameters:
            client_id: The ID of the OAuth client making the request.
                (This parameter is not used. This comes from the auth enricher.)
            requested_audiences: A list of strings specifying the audiences
                to request.
            requested_scopes: A list of scopes to request when obtaining the
                refreshed tokens.  This list may only be a subset of the scopes
                that were initially granted to the client.  A scope increase may
                not be requested during refresh. A scope increase requires a new
                authorization (login).
            auth_enricher: Function to layer in the application of client credentials.
            extra: Dict of extra parameters to pass to the token endpoint.

        Returns:
            Returns the token endpoint response payload upon success as a json
                object. If an error condition is detected, either from the HTTP
                layer or from a payload that indicates a failure, an exception
                will be raised.
        """
        if extra is None:
            extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        _extra = {k: v for k, v in extra.items() if v is not None}
        data = {
            **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            "grant_type": "client_credentials",
            # Client id, secret, or assertion come from enricher.
            # 'client_id': client_id,
            # 'client_secret': client_secret
            # 'client_assertion_type':
            #        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            #  client_assertion': signed_jwt
        }
        if requested_scopes:
            data["scope"] = " ".join(requested_scopes)
        if requested_audiences:
            data["audience"] = " ".join(requested_audiences)

        return self._checked_call(data, auth_enricher)

    def get_token_from_code(
        self,
        redirect_uri: str,
        client_id: str,
        code: str,
        code_verifier: str,
        auth_enricher: Optional[EnricherFuncType] = None,
        # extra=None, # This should be in the auth request, not the code redemption.
    ) -> Dict:
        """
        Obtain tokens using an authorization code.

        Returns:
            Returns the token endpoint response payload upon success as a json
                object. If an error condition is detected, either from the HTTP
                layer or from a payload that indicates a failure, an exception
                will be raised.
        """
        # if extra is None:
        #     extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        # _extra = {k: v for k, v in extra.items() if v is not None}
        data = {
            # **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": code_verifier,
            # 'client_id': client_id,  # The job of the enricher.
        }

        return self._checked_call(data, auth_enricher)

    def poll_for_token_from_device_code(
        self,
        client_id: str,
        device_code: str,
        timeout: int,
        poll_interval: int = 5,  # Default poll interval specified in RFC 8628
        auth_enricher: Optional[EnricherFuncType] = None,
        # extra=None,  # This should be in the auth request, not the code redemption.
    ) -> Dict:
        """
        Poll for the completion of a device code login.

        Returns:
            Returns the token endpoint response payload upon success as a json
                object. If an error condition is detected, either from the HTTP
                layer or from a payload that indicates a failure, an exception
                will be raised.
        """
        # if extra is None:
        #    extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        # _extra = {k: v for k, v in extra.items() if v is not None}
        data = {
            # **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            # 'client_id': client_id,  # The job of the enricher.
        }
        return self._polling_checked_call(
            data, timeout=timeout, poll_interval=poll_interval, auth_enricher=auth_enricher
        )

    def get_token_from_password(
        self,
        client_id: str,
        username: str,
        password: str,
        requested_scopes: List[str] = None,
        requested_audiences: List[str] = None,
        auth_enricher: Optional[EnricherFuncType] = None,
        extra: Dict = None,
    ) -> Dict:
        """
        Obtain tokens using a username and password and the resource owner
        grant OAuth flow.

        Parameters:
            client_id: The ID of the OAuth client making the request.
                (This parameter is not used. This comes from the auth enricher.)
            username: The username used for authentication.
            password: The password used for authentication.
            requested_scopes: A list of scopes to request when obtaining the
                refreshed tokens.  This list may only be a subset of the scopes
                that were initially granted to the client.  A scope increase may
                not be requested during refresh. A scope increase requires a new
                authorization (login).
            requested_audiences: A list of strings specifying the audiences
                to request.
            auth_enricher: Function to layer in the application of client credentials.
            extra: Dict of extra parameters to pass to the token endpoint.

        Returns:
            Returns the token endpoint response payload upon success as a json
                object. If an error condition is detected, either from the HTTP
                layer or from a payload that indicates a failure, an exception
                will be raised.
        """
        if extra is None:
            extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        _extra = {k: v for k, v in extra.items() if v is not None}
        data = {
            **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            "grant_type": "password",
            "username": username,
            "password": password,
            # "client_id": client_id, The job of the auth_enricher.
        }
        if requested_scopes:
            data["scope"] = " ".join(requested_scopes)
        if requested_audiences:
            data["audience"] = " ".join(requested_audiences)

        return self._checked_call(data, auth_enricher)
