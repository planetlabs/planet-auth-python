# Copyright 2025 Planet Labs PBC.
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

from planet_auth.oidc.api_clients.api_client import OidcApiClient, OidcApiClientException, _RequestParamsType, _RequestAuthType


class DynamicClientRegistrationApiException(OidcApiClientException):
    def __init__(self, message=None, raw_response=None):
        super().__init__(message, raw_response)


class DynamicClientRegistrationApiClient(OidcApiClient):
    """
    Low level client for Dynamic Client Registration.
    See https://datatracker.ietf.org/doc/html/rfc7591
    """

    def __init__(self, dynamic_client_registration_uri: Optional[str] = None, auth_server: Optional[str] = None):
        """
        Create a new OIDC discovery API client.
        """
        super().__init__(endpoint_uri=dynamic_client_registration_uri)

    @staticmethod
    def _check_dynamic_client_registration_response(json_response: Dict) -> Dict:
        raise DynamicClientRegistrationApiException(message="Not implemented DCR protcol checks")
        # TODO - protocol specific checks
        return json_response

    def _checked_dynamic_client_registration_call(
        self, request_params: _RequestParamsType, auth: Optional[_RequestAuthType]
    ) -> Dict:
        json_response = self._checked_post_json_response(params=request_params, request_auth=auth)
        return self._check_dynamic_client_registration_response(json_response)

    def register_client(self) -> Dict:
        """
        Register a new client using Dynamic Client Registration.
        """
        reg_payload = {
            "foo": "bar"
        }
        return self._checked_dynamic_client_registration_call(request_params=reg_payload, auth=None)

