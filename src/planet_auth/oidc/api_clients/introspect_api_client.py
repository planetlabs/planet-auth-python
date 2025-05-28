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

from typing import Dict, Optional

from planet_auth.auth_exception import InvalidTokenException
from planet_auth.logging.events import AuthEvent
from planet_auth.oidc.api_clients.api_client import (
    OidcApiClient,
    OidcApiClientException,
    EnricherFuncType,
    _RequestAuthType,
    _RequestParamsType,
)


class IntrospectionApiException(OidcApiClientException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class IntrospectionRejectionTokenException(InvalidTokenException):
    def __init__(self, event: AuthEvent = AuthEvent.TOKEN_INVALID_INTROSPECTION_REJECTION, **kwargs):
        super().__init__(event=event, **kwargs)


class IntrospectionApiClient(OidcApiClient):
    """
    Low level network client for the "introspection" OAuth2/OIDC
    network endpoint.  Responses are defined by RFC 7662.

    All invalid responses or responses that indicate that a token
    is not active will result in an exception.
    """

    def __init__(self, introspect_uri: str):
        """
        Create a new token introspection API client
        """
        super().__init__(endpoint_uri=introspect_uri)

    @staticmethod
    def _check_introspection_response(json_response: Dict) -> Dict:
        if not isinstance(json_response.get("active"), bool):
            raise IntrospectionApiException(
                message="Unrecognized response: 'active' field was not present or was not boolean in the response."
            )
        # This is a valid response for an invalid token.
        # The decision to throw mirrors the behavior of PyJWT validation failures.
        if not json_response.get("active"):
            raise IntrospectionRejectionTokenException(message="Token is not active according to issuer introspection")
        return json_response

    @staticmethod
    def check_introspection_response(json_response: Dict) -> Dict:
        # Like above, but for external utility consumption
        if not json_response:
            raise IntrospectionApiException(message="Invalid response: introspection result cannot be empty.")
        return IntrospectionApiClient._check_introspection_response(json_response)

    def _checked_introspection_call(
        self, validate_params: _RequestParamsType, auth: Optional[_RequestAuthType]
    ) -> Dict:
        json_response = self._checked_post_json_response(validate_params, auth)
        return self._check_introspection_response(json_response)

    def _validate_token(self, token: str, token_hint: str, auth_enricher: Optional[EnricherFuncType] = None) -> Dict:
        params = {
            "token": token,
            "token_type_hint": token_hint,
        }
        request_auth = None
        if auth_enricher:
            params, request_auth = auth_enricher(params, self._endpoint_uri)
        return self._checked_introspection_call(params, request_auth)

    def validate_access_token(self, access_token: str, auth_enricher: Optional[EnricherFuncType] = None) -> Dict:
        """
        Validate an access token against the OAuth introspection endpoint.
        Invalid tokens will result in an exception.
        """
        return self._validate_token(access_token, "access_token", auth_enricher)

    def validate_id_token(self, id_token: str, auth_enricher: Optional[EnricherFuncType] = None) -> Dict:
        """
        Validate an ID token against the OAuth introspection endpoint.
        Invalid tokens will result in an exception.
        """
        return self._validate_token(id_token, "id_token", auth_enricher)

    def validate_refresh_token(self, refresh_token: str, auth_enricher: Optional[EnricherFuncType] = None) -> Dict:
        """
        Validate a refresh token against the OAuth introspection endpoint.
        Invalid tokens will result in an exception.
        """
        return self._validate_token(refresh_token, "refresh_token", auth_enricher)
