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

from typing import Optional
from planet_auth.oidc.api_clients.api_client import (
    OidcApiClient,
    EnricherFuncType,
    _RequestParamsType,
    _RequestAuthType,
)

# class RevocationAPIException(OidcApiClientException):
#
#   def __init__(self, message=None, raw_response=None):
#        super().__init__(message, raw_response)


class RevocationApiClient(OidcApiClient):
    """
    Low level API client for the OAuth Token Revocation endpoint. See
    RFC 7009 - OAuth 2.0 Token Revocation for protocol details.
    """

    def __init__(self, revocation_uri: str):
        """
        Create a new Revocation API Client.
        """
        super().__init__(endpoint_uri=revocation_uri)

    def _checked_revocation_call(self, params: _RequestParamsType, request_auth: Optional[_RequestAuthType]) -> None:
        self._checked_post(params, request_auth)
        # if response.content:
        #    # No payload expected on success. All HTTP and known json error
        #    # checks in base class.
        #    raise RevocationAPIException(
        #        message='Unexpected response from OIDC Revocation endpoint',
        #        raw_response=response)

    def _revoke_token(self, token: str, token_hint: str, auth_enricher: Optional[EnricherFuncType] = None) -> None:
        params = {
            "token": token,
            "token_type_hint": token_hint,
            # 'client_id': client_id # FIXME? Required? Part of enrichment?
        }
        request_auth = None
        if auth_enricher:
            params, request_auth = auth_enricher(params, self._endpoint_uri)
        self._checked_revocation_call(params, request_auth)

    def revoke_access_token(self, access_token: str, auth_enricher: Optional[EnricherFuncType] = None) -> None:
        """
        Revoke the specified access token.
        """
        self._revoke_token(access_token, "access_token", auth_enricher)

    def revoke_refresh_token(self, refresh_token: str, auth_enricher: Optional[EnricherFuncType] = None) -> None:
        """
        Revoke the specified refresh token.
        """
        return self._revoke_token(refresh_token, "refresh_token", auth_enricher)
