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

from typing import Dict, List
from planet_auth.oidc.api_clients.api_client import OidcApiClient, OidcApiClientException


class JwksApiException(OidcApiClientException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class JwksApiClient(OidcApiClient):
    """
    Low level API client for the OAuth JWKS endpoint.
    See RFC 7517 - JSON Web Key (JWK) and
    RFC 8414 - OAuth 2.0 Authorization Server Metadata
    for more information.
    """

    def __init__(self, jwks_uri: str):
        """
        Create a JWKS endpoint client
        """
        super().__init__(endpoint_uri=jwks_uri)

    def _checked_fetch(self):
        return self._checked_get_json_response(None, None)

    def jwks(self) -> Dict:
        """
        Fetch metadata from the JWKS endpoint.

        Returns:
            The full jwks response from the endpoint. An exception will be
                raised when an error occurs.
        """
        return self._checked_fetch()

    def jwks_keys(self) -> List:
        """
        Fetch keys from the JWKS endpoint.

        Returns:
            Just the jwks key set from the endpoint. An exception will be
                raised when an error occurs.
        """
        jwks_response = self.jwks()
        jwks_keys = jwks_response.get("keys")
        if not jwks_keys:
            raise JwksApiException(message='JWKS endpoint response did not include "keys" data')
        return jwks_keys
