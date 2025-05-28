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

from cryptography.hazmat.primitives import serialization as crypto_serialization

from planet_auth.auth_client import AuthClientConfigException
from planet_auth.oidc.api_clients.api_client import EnricherPayloadType, EnricherReturnType
from planet_auth.oidc.api_clients.oidc_request_auth import prepare_private_key_assertion_auth_payload
from planet_auth.oidc.auth_client import OidcAuthClient, OidcAuthClientConfig


class OidcAuthClientWithPubKeyClientConfig(OidcAuthClientConfig, ABC):
    """
    Mix-in base class for OIDC auth clients that make use of a client public/private keypair
    to perform client authentication.
    """

    def __init__(
        self,
        client_privkey: str = None,
        client_privkey_file: str = None,
        client_privkey_password: str = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        if client_privkey:
            self._data["client_privkey"] = client_privkey
        if client_privkey_file:
            self._data["client_privkey_file"] = client_privkey_file
        if client_privkey_password:
            self._data["client_privkey_password"] = client_privkey_password

        # Loaded JIT. Not in the serialized self._data representation.
        self._client_privkey_data = None

    def check_data(self, data):
        super().check_data(data)
        if not data.get("client_privkey") and not data.get("client_privkey_file"):
            raise AuthClientConfigException(
                message="One of client_privkey or client_privkey_file must be"
                " configured for {} client".format(self.__class__.__name__)
            )

    def client_privkey(self) -> str:
        return self.lazy_get("client_privkey")

    def client_privkey_data(self):
        # TODO: handle key refresh if the file has changed?
        if not self._client_privkey_data:
            self._load_private_key()
        return self._client_privkey_data

    def client_privkey_file(self) -> str:
        return self.lazy_get("client_privkey_file")

    def client_privkey_password(self) -> str:
        return self.lazy_get("client_privkey_password")

    # Recast is to catches bad passwords. Too broad?
    @AuthClientConfigException.recast(TypeError, ValueError)
    def _load_private_key(self):
        # TODO: also handle loading of JWK keys? Fork based on filename
        #       or detect?
        # import jwt
        # priv_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))

        config_privkey_password = self.client_privkey_password()
        if config_privkey_password and type(config_privkey_password) is str:
            privkey_password = config_privkey_password.encode()
        else:
            privkey_password = config_privkey_password

        config_privkey_literal = self.client_privkey()
        if config_privkey_literal:
            if type(config_privkey_literal) is str:
                _privkey_literal = config_privkey_literal.encode()
            else:
                _privkey_literal = config_privkey_literal

            priv_key = crypto_serialization.load_pem_private_key(_privkey_literal, password=privkey_password)
            if not priv_key:
                raise AuthClientConfigException(
                    message="Unable to load private key literal from configuration for {} auth client.".format(
                        self.__class__.__name__
                    )
                )
        else:
            _config_privkey_file = self.client_privkey_file()
            if not _config_privkey_file:
                raise AuthClientConfigException(
                    message="Private key must be configured for {} auth client.".format(self.__class__.__name__)
                )
            with open(_config_privkey_file, "rb") as key_file:
                priv_key = crypto_serialization.load_pem_private_key(key_file.read(), password=privkey_password)
                if not priv_key:
                    raise AuthClientConfigException(
                        message='Unable to load private key from file "{}"'.format(_config_privkey_file)
                    )

        self._client_privkey_data = priv_key

    @classmethod
    def meta(cls):
        return {
            "config_hints": super().meta().get("config_hints")
            + [
                {
                    "config_key": "client_privkey",
                    "config_key_name": "Client private key literal",
                    "config_key_description": "A literal private key to store in the auth client configuration."
                    "  Clients require one of a private key literal or a private key file.",
                },
                {
                    "config_key": "client_privkey_file",
                    "config_key_name": "Client private key file",
                    "config_key_description": "Path to a file containing the client's private key."
                    "  Clients require one of a private key literal or a private key file.",
                },
                {
                    "config_key": "client_privkey_password",
                    "config_key_name": "Private key password",
                    "config_key_description": "Optional password protecting the private key",
                },
            ]
        }


class OidcAuthClientWithClientPubkey(OidcAuthClient, ABC):
    """
    Mix-in base class for OIDC auth clients that make use of a client public/private keypair
    to perform client authentication.
    """

    def __init__(self, client_config: OidcAuthClientWithPubKeyClientConfig):
        super().__init__(client_config)
        self._oidc_pubkey_client_config = client_config

    def _client_auth_enricher(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        auth_assertion_payload = prepare_private_key_assertion_auth_payload(
            audience=audience,
            client_id=self._oidc_pubkey_client_config.client_id(),
            private_key=self._oidc_pubkey_client_config.client_privkey_data(),
            ttl=300,
        )
        enriched_payload = {**raw_payload, **auth_assertion_payload}
        return enriched_payload, None
