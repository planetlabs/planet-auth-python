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

from typing import Dict
from planet_auth.oidc.api_clients.api_client import OidcApiClient


# class UserinfoApiException(OidcApiClientException):
#    def __init__(self, **kwargs):
#        super().__init__(**kwargs)


class UserinfoApiClient(OidcApiClient):
    """
    Low level network client for the "Userinfo" OAuth2/OIDC
    network endpoint.
    """

    def __init__(self, userinfo_uri: str):
        """
        Create a new token Userinfo API client
        """
        super().__init__(endpoint_uri=userinfo_uri)

    def _checked_userinfo_call(self, access_token: str) -> Dict:
        return self._checked_get_json_response(params=None, request_auth=self.TokenBearerAuth(access_token))

    def userinfo_from_access_token(self, access_token: str) -> Dict:
        """
        Obtain user information from the authorization server for the user who owns
        the presented access token.

        Parameters:
            access_token: User access token.
        """
        return self._checked_userinfo_call(access_token)
