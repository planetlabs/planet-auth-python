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

from planet_auth.oidc.api_clients.api_client import EnricherPayloadType, EnricherReturnType
from planet_auth.auth_client import AuthClientConfigException
from planet_auth.oidc.api_clients.oidc_request_auth import (
    prepare_client_secret_request_auth,
    prepare_client_secret_auth_payload,
)
from planet_auth.oidc.auth_client import OidcAuthClient, OidcAuthClientConfig


# TODO: Can I implement these as RequestAuthenticator? Good dog food.
class OidcAuthClientWithClientSecretClientConfig(OidcAuthClientConfig, ABC):
    """
    Mix-in base class for OIDC auth clients that make use of a client secret.
    """

    def __init__(self, client_secret: str = None, **kwargs):
        super().__init__(**kwargs)
        if client_secret:
            self._data["client_secret"] = client_secret

    def client_secret(self) -> str:
        return self.lazy_get("client_secret")

    def check_data(self, data):
        super().check_data(data)
        if not data.get("client_secret"):
            raise AuthClientConfigException(
                message="client_secret must be configured for {} client.".format(self.__class__.__name__)
            )

    @classmethod
    def meta(cls):
        return {
            "config_hints": super().meta().get("config_hints")
            + [
                {
                    "config_key": "client_secret",
                    "config_key_name": "Client secret",
                    "config_key_description": "Client shared secret known only to the client and the authorization server",
                }
            ]
        }


class OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment(OidcAuthClient, ABC):
    """
    Mix-in base class for OIDC auth clients that make use of a client secret
    to perform client authentication.
    """

    def __init__(self, client_config: OidcAuthClientWithClientSecretClientConfig):
        super().__init__(client_config)
        self._oidc_client_secret_client_config = client_config

    def _client_auth_enricher(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        return raw_payload, prepare_client_secret_request_auth(
            self._oidc_client_secret_client_config.client_id(), self._oidc_client_secret_client_config.client_secret()
        )


class OidcAuthClientWithClientSecret_PayloadAuthEnrichment(OidcAuthClient, ABC):
    """
    Mix-in base class for OIDC auth clients that make use of a client secret
    to perform client authentication.
    """

    def __init__(self, client_config: OidcAuthClientWithClientSecretClientConfig):
        super().__init__(client_config)
        self._oidc_client_secret_client_config = client_config

    def _client_auth_enricher(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        auth_payload = prepare_client_secret_auth_payload(
            client_id=self._oidc_client_secret_client_config.client_id(),
            client_secret=self._oidc_client_secret_client_config.client_secret(),
        )
        enriched_payload = {**raw_payload, **auth_payload}
        return enriched_payload, None
