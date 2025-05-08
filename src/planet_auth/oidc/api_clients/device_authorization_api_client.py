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

from typing import Dict, List, Optional

from planet_auth.oidc.api_clients.api_client import (
    OidcApiClient,
    OidcApiClientException,
    EnricherFuncType,
    _RequestParamsType,
    _RequestAuthType,
)


class DeviceAuthorizationApiException(OidcApiClientException):
    def __init__(self, message=None, raw_response=None):
        super().__init__(message, raw_response)


class DeviceAuthorizationApiClient(OidcApiClient):
    """
    Low level network client for the "device_authorization_endpoint" OAuth2/OIDC
    network endpoint.  This endpoint is defined by RFC 8628. See https://www.rfc-editor.org/rfc/rfc8628

    All invalid responses or error responses will result in an exception.
    """

    def __init__(self, device_authorization_uri: str):
        super().__init__(endpoint_uri=device_authorization_uri)

    @staticmethod
    def _prep_device_code_request_payload(
        client_id,
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        extra: Optional[Dict],
    ) -> Dict:
        if extra is None:
            extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        _extra = {k: v for k, v in extra.items() if v is not None}

        data = {
            **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            # "client_id": client_id,  # The job of the enricher.
        }
        if requested_scopes:
            data["scope"] = " ".join(requested_scopes)
        if requested_audiences:
            data["audience"] = " ".join(requested_audiences)

        return data

    @staticmethod
    def _check_device_auth_response(json_response: Dict) -> Dict:
        # Protocol endpoint specific response checks
        if not json_response.get("device_code"):
            raise DeviceAuthorizationApiException(
                "Unrecognized response: 'device_code' field was not present in the response."
            )
        if not json_response.get("user_code"):
            raise DeviceAuthorizationApiException(
                "Unrecognized response: 'user_code' field was not present in the response."
            )
        if not json_response.get("verification_uri"):
            raise DeviceAuthorizationApiException(
                "Unrecognized response: 'verification_uri' field was not present in the response."
            )
        if not json_response.get("expires_in"):
            raise DeviceAuthorizationApiException(
                "Unrecognized response: 'expires_in' field was not present in the response."
            )
        # verification_uri_complete and interval are optional under the spec, so we don't force them to be present.
        return json_response

    def _checked_request_device_code_call(
        self, request_params: _RequestParamsType, request_auth: Optional[_RequestAuthType]
    ) -> Dict:
        json_response = self._checked_post_json_response(request_params, request_auth)
        return self._check_device_auth_response(json_response)

    def request_device_code(
        self,
        client_id: str,
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        auth_enricher: Optional[EnricherFuncType],
        extra,
    ) -> Dict:
        request_params = self._prep_device_code_request_payload(
            client_id=client_id,
            requested_scopes=requested_scopes,
            requested_audiences=requested_audiences,
            extra=extra,
        )
        request_auth = None
        if auth_enricher:
            request_params, request_auth = auth_enricher(request_params, self._endpoint_uri)

        return self._checked_request_device_code_call(request_params, request_auth)
