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

from abc import ABC
from requests import Session, Response
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from typing import Callable, Dict, Optional, Tuple
from urllib3.util.retry import Retry

from planet_auth.auth_client import AuthClientException
from planet_auth.constants import X_PLANET_APP_HEADER, X_PLANET_APP
from planet_auth.util import parse_content_type

EnricherPayloadType = Dict
# EnricherAudType = str
EnricherReturnType = Tuple[Dict, Optional[AuthBase]]
EnricherFuncType = Callable[[EnricherPayloadType, str], EnricherReturnType]

_RequestAuthType = AuthBase
_RequestParamsType = Dict  # Requests allows a lot more, but constrain our use.
_RequestResponseType = Response


class OidcApiClient(ABC):
    """
    Base class that provides utility functions common to interactions with
    any of the OIDC endpoints.
    """

    # Most of the users of OidcApiClient will need some sort of "enriched" auth,
    # that takes client auth parameters from some facet of the client itself.
    # Generally, this will be some combination of the client ID and secret
    # and may be a header or payload adjustment.   But sometimes, we just
    # need to use an Authorization header.
    # TODO: dog-food - use our own RequestAuthenticator like we do for the
    #  static API key auth client
    class TokenBearerAuth(AuthBase):
        def __init__(self, token):
            self._token = token

        def __call__(self, r):
            r.headers["Authorization"] = "Bearer " + self._token
            return r

    def __init__(self, endpoint_uri: str):
        self._endpoint_uri = endpoint_uri

        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429], allowed_methods=["POST", "GET"])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session = Session()
        self._session.mount("https://", adapter)
        # self._session.mount("http://", adapter)

    def __check_http_error(self, response: _RequestResponseType) -> None:
        if not response.ok:
            raise OidcApiClientException(
                message="HTTP error from OIDC endpoint at {}: {}: {}".format(
                    self._endpoint_uri, response.status_code, response.reason
                ),
                raw_response=response,
            )

    def __check_oidc_payload_json_error(self, response: _RequestResponseType) -> None:
        if response.content:
            ct = parse_content_type(response.headers.get("content-type"))
            if not ct["content-type"] == "application/json":
                return

            json_response = response.json()

            # Irritatingly, I've seen multiple error payload schemas.
            # Most should adhere to RFC 6749.
            if json_response.get("error"):
                raise OidcApiClientException(
                    message="Error from OIDC endpoint at {}: {}: {}".format(
                        self._endpoint_uri, json_response.get("error"), json_response.get("error_description")
                    ),
                    error_code=json_response.get("error"),
                    raw_response=response,
                )

            if json_response.get("errorCode"):
                raise OidcApiClientException(
                    message="Error from OIDC endpoint at {}: {}: {}".format(
                        self._endpoint_uri, json_response.get("errorCode"), json_response.get("errorSummary")
                    ),
                    error_code=json_response.get("errorCode"),
                    raw_response=response,
                )

    @staticmethod
    def __checked_json_response(response: _RequestResponseType) -> Dict:
        json_response = None
        if response.content:
            ct = parse_content_type(response.headers.get("content-type"))
            if not ct["content-type"] == "application/json":
                raise OidcApiClientException(
                    message='Expected json content-type, but got "{}"'.format(response.headers.get("content-type")),
                    raw_response=response,
                )
            json_response = response.json()
        if not json_response:
            raise OidcApiClientException(
                messsage="Response was not understood. Expected JSON response payload, but none was found.",
                raw_response=response,
            )
        return json_response

    def __check_response(self, response: _RequestResponseType) -> None:
        # Check for the json error first so we throw a more specific parsed
        # error if we understand it, regardless of HTTP status code.
        self.__check_oidc_payload_json_error(response)
        self.__check_http_error(response)

    def _checked_get(
        self, params: Optional[_RequestParamsType], request_auth: Optional[_RequestAuthType]
    ) -> _RequestResponseType:
        response = self._session.get(
            self._endpoint_uri,
            params=params,
            auth=request_auth,
            headers={"Accept": "application/json", X_PLANET_APP_HEADER: X_PLANET_APP},
        )
        self.__check_response(response)
        return response

    def _checked_post(
        self, params: Optional[_RequestParamsType], request_auth: Optional[_RequestAuthType]
    ) -> _RequestResponseType:
        response = self._session.post(
            self._endpoint_uri,
            # Note: is the data/params crossing confusing? This was born out
            #       of some OIDC services accepting either in some cases,
            #       and others not doing so.
            data=params,
            auth=request_auth,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                X_PLANET_APP_HEADER: X_PLANET_APP,
            },
        )
        self.__check_response(response)
        return response

    def _checked_post_json_response(
        self, params: Optional[_RequestParamsType], request_auth: Optional[_RequestAuthType]
    ) -> Dict:
        return self.__checked_json_response(self._checked_post(params, request_auth))

    def _checked_get_json_response(
        self, params: Optional[_RequestParamsType], request_auth: Optional[_RequestAuthType]
    ) -> Dict:
        return self.__checked_json_response(self._checked_get(params, request_auth))


class OidcApiClientException(AuthClientException):
    def __init__(self, error_code=None, raw_response=None, **kwargs):
        super().__init__(**kwargs)
        self.raw_response = raw_response
        self.error_code = error_code
