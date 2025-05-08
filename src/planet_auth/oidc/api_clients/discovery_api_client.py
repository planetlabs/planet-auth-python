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

from planet_auth.oidc.api_clients.api_client import OidcApiClient, OidcApiClientException


class DiscoveryApiException(OidcApiClientException):
    def __init__(self, message=None, raw_response=None):
        super().__init__(message, raw_response)


class DiscoveryApiClient(OidcApiClient):
    """
    Low level client for OIDC discovery.
    See https://openid.net/specs/openid-connect-discovery-1_0.html for details.
    """

    # TODO: Revisit if this is where I should cache. I did work
    #       on the JWKS client after this, and I think it is more mature.
    def __init__(self, discovery_uri: Optional[str] = None, auth_server: Optional[str] = None):
        """
        Create a new OIDC discovery API client.
        """
        if discovery_uri:
            d_uri = discovery_uri
        else:
            if auth_server:
                if auth_server.endswith("/"):
                    d_uri = auth_server + ".well-known/openid-configuration"
                else:
                    d_uri = auth_server + "/.well-known/openid-configuration"
            else:
                raise DiscoveryApiException("One of discovery_uri or auth_server must be provided")

        super().__init__(d_uri)
        self._oidc_discovery: Dict = None  # type: ignore

    def do_discovery(self) -> None:
        """
        Contact the discovery endpoint, download discovery information, and cache the
        results inside the client.
        """
        self._oidc_discovery = self._checked_get_json_response(None, None)

    def do_discovery_jit(self) -> None:
        """
        Contact the discovery endpoint and download and cache the results
        only if discovery had not previously been performed and cached.
        """
        if not self._oidc_discovery:
            self.do_discovery()

    def discovery(self) -> Dict:
        """
        Return the discovery information.  If the information was previously fetched,
        the cached information will be returned, and no network connection will be made.
        """
        self.do_discovery_jit()
        return self._oidc_discovery
