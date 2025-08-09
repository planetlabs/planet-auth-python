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

import pathlib
from typing import Optional, Union

from planet_auth.auth_client import AuthClientConfig, AuthClient
from planet_auth.credential import Credential
from planet_auth.request_authenticator import CredentialRequestAuthenticator, SimpleInMemoryRequestAuthenticator


class NoOpCredential(Credential):
    def load(self):
        pass

    def save(self):
        pass


class NoOpAuthClientConfig(AuthClientConfig):
    """
    Auth client that does nothing.
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "none",
            "auth_client_class": NoOpAuthClient,
            "display_name": "NoOp Auth",
            "description": "Do not perform any authentication.",
            "config_hints": [],
        }


class NoOpAuthClient(AuthClient):
    def __init__(self, client_config: NoOpAuthClientConfig):
        super().__init__(client_config)
        self._noop_client_config = client_config

    def login(
        self, allow_open_browser: Optional[bool] = False, allow_tty_prompt: Optional[bool] = False, **kwargs
    ) -> Credential:
        return NoOpCredential()

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> CredentialRequestAuthenticator:
        return SimpleInMemoryRequestAuthenticator(token_body=None)

    def refresh(self, refresh_token, requested_scopes) -> Credential:
        return self.login()

    def validate_access_token_remote(self, access_token: str) -> dict:
        return {}

    def validate_access_token_local(
        self, access_token: str, required_audience: str = None, scopes_anyof: list = None
    ) -> dict:
        return {}

    def validate_id_token_remote(self, id_token: str) -> dict:
        return {}

    def validate_id_token_local(self, id_token: str) -> dict:
        return {}

    def validate_refresh_token_remote(self, refresh_token: str) -> dict:
        return {}

    def revoke_access_token(self, access_token: str):
        pass

    def revoke_refresh_token(self, refresh_token: str):
        pass

    def get_scopes(self):
        return []

    def can_login_unattended(self) -> bool:
        return True
