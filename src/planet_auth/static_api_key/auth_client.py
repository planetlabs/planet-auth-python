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

import planet_auth.logging.auth_logger
from planet_auth.credential import Credential
from planet_auth.auth_client import AuthClient, AuthClientConfig, AuthClientException
from planet_auth.static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator
from planet_auth.static_api_key.static_api_key import FileBackedApiKey

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class StaticApiKeyAuthClientException(AuthClientException):
    def __init__(self, message=None):
        super().__init__(message=message)


class StaticApiKeyAuthClientConfig(AuthClientConfig):
    def __init__(self, api_key=None, bearer_token_prefix="Bearer", **kwargs):
        super().__init__(**kwargs)
        if api_key:
            self._data["api_key"] = api_key
            if bearer_token_prefix:
                # Only save the prefix if we have a key.
                # the config file base class only expects _data to be whole, never partial.
                # (Static API keys auth client is a funny case, where an AuthClientConfig
                # and a Credential object are pretty much the same.)
                self._data["bearer_token_prefix"] = bearer_token_prefix

    def api_key(self) -> str:
        return self.lazy_get("api_key")

    def bearer_token_prefix(self) -> str:
        return self.lazy_get("bearer_token_prefix")

    @classmethod
    def meta(cls):
        return {
            "client_type": "static_apikey",
            "auth_client_class": StaticApiKeyAuthClient,
            "display_name": "API Key",
            "description": "Static API key authentication.",
            "config_hints": [
                {
                    "config_key": "api_key",
                    "config_key_name": "API Key",
                    "config_key_description": "Static API key used to authenticate requests",
                },
                {
                    "config_key": "bearer_token_prefix",
                    "config_key_name": "Bearer Token Prefix",
                    "config_key_description": "Prefix used Authorization headers with the API key",
                },
            ],
        }


class StaticApiKeyAuthClient(AuthClient):
    def __init__(self, client_config: StaticApiKeyAuthClientConfig):
        super().__init__(client_config)
        self._static_api_key_config = client_config

    def login(
        self, allow_open_browser: Optional[bool] = False, allow_tty_prompt: Optional[bool] = False, **kwargs
    ) -> FileBackedApiKey:
        if self._static_api_key_config.api_key():
            return FileBackedApiKey(
                api_key=self._static_api_key_config.api_key(),
                prefix=self._static_api_key_config.bearer_token_prefix(),
                api_key_file=self._static_api_key_config.path(),
            )
        else:
            raise StaticApiKeyAuthClientException(
                message="Cannot return credential object from login() for static API key AuthClient when no API key is configured."
            )

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> FileBackedApiKeyRequestAuthenticator:
        # If an API key has been configured in the client config, use that and ignore
        # any separate credential file.
        storage_provider = self._auth_client_config.storage_provider()
        if self._static_api_key_config.api_key():
            _credential = FileBackedApiKey(
                api_key=self._static_api_key_config.api_key(),
                prefix=self._static_api_key_config.bearer_token_prefix(),
                api_key_file=self._static_api_key_config.path(),
                storage_provider=self._static_api_key_config.storage_provider(),
            )
        else:
            if isinstance(credential, pathlib.Path):
                _credential = FileBackedApiKey(api_key_file=credential, storage_provider=storage_provider)
            elif isinstance(credential, FileBackedApiKey):
                _credential = credential
            elif credential is None:
                # This will be brain-dead until update_credential() or update_credential_data()
                # is called.  This is useful for initializing properly typed credential objects.
                _credential = FileBackedApiKey(storage_provider=storage_provider)
            else:
                raise TypeError(
                    f"{type(self).__name__} does not support {type(credential)} credentials.  Use file path or FileBackedApiKey."
                )

        return FileBackedApiKeyRequestAuthenticator(api_key_credential=_credential)

    def can_login_unattended(self) -> bool:
        # We could enhance login() to prompt for a static API key
        # if it's not in the config, but the current implementation
        # considered it a required field, so this should always be true.
        return True
