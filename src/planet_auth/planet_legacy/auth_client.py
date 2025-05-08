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

import getpass
import pathlib
import jwt
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Union

import planet_auth.logging.auth_logger
from planet_auth.auth_client import AuthClientConfig, AuthClient, AuthClientException, AuthClientConfigException
from planet_auth.constants import X_PLANET_APP_HEADER, X_PLANET_APP
from planet_auth.credential import Credential
from planet_auth.planet_legacy.legacy_api_key import FileBackedPlanetLegacyApiKey
from planet_auth.planet_legacy.request_authenticator import PlanetLegacyRequestAuthenticator
from planet_auth.request_authenticator import CredentialRequestAuthenticator
from planet_auth.util import parse_content_type

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class PlanetLegacyAuthClientConfig(AuthClientConfig):
    """
    Configuration required for [planet_auth.PlanetLegacyAuthClient][]
    """

    def __init__(self, legacy_auth_endpoint=None, api_key=None, **kwargs):
        super().__init__(**kwargs)
        if api_key:
            self._data["api_key"] = api_key
        if legacy_auth_endpoint:
            self._data["legacy_auth_endpoint"] = legacy_auth_endpoint

    def check_data(self, data):
        super().check_data(data)
        if not data.get("legacy_auth_endpoint"):
            raise AuthClientConfigException(
                message="legacy_auth_endpoint must be configured for Planet Legacy auth clients."
            )

    def api_key(self) -> str:
        return self.lazy_get("api_key")

    def legacy_auth_endpoint(self) -> str:
        return self.lazy_get("legacy_auth_endpoint")

    @classmethod
    def meta(cls):
        return {
            "client_type": "planet_legacy",
            "auth_client_class": PlanetLegacyAuthClient,
            "display_name": "Planet Legacy Auth",
            "description": "Planet legacy authentication protocols.  Not recommended for new applications.",
            "config_hints": [
                {
                    "config_key": "legacy_auth_endpoint",
                    "config_key_name": "Planet Legacy Authentication Endpoint",
                    "config_key_description": "API endpoint used to perform user authentication against the Planet cloud service.",
                    # "config_key_default": "",
                },
                {
                    "config_key": "api_key",
                    "config_key_name": "Planet API Key",
                    "config_key_description": "Planet API key used to authenticate requests",
                },
            ],
        }


class PlanetLegacyAuthClientException(AuthClientException):
    def __init__(self, raw_response=None, **kwargs):
        super().__init__(**kwargs)
        self.raw_response = raw_response


class PlanetLegacyAuthClient(AuthClient):
    """
    Implementation of the AuthClient that interacts with Planet's API key
    auth interfaces.
    """

    def __init__(self, legacy_client_config: PlanetLegacyAuthClientConfig):
        super().__init__(legacy_client_config)
        self._legacy_client_config = legacy_client_config

        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429], allowed_methods=["POST", "GET"])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session = Session()
        self._session.mount("https://", adapter)
        # self._session.mount("http://", adapter)

    @staticmethod
    def _prepare_auth_payload(username, password):
        data = {"email": username, "password": password}
        return data

    def _check_http_error(self, response):
        if not response.ok:
            raise PlanetLegacyAuthClientException(
                message="HTTP error from endpoint at {}: {}: {}".format(
                    self._legacy_client_config.legacy_auth_endpoint(), response.status_code, response.reason
                ),
                raw_response=response,
            )

    def _check_json_payload(self, response):
        json_response = None
        if response.content:
            ct = parse_content_type(response.headers.get("content-type"))
            if not ct["content-type"] == "application/json":
                raise PlanetLegacyAuthClientException(
                    message='Expected json content-type, but got "{}"'.format(response.headers.get("content-type")),
                    raw_response=response,
                )
            json_response = response.json()
        if not json_response:
            raise PlanetLegacyAuthClientException(
                message="Response from authentication endpoint {}"
                " was not understood. Expected JSON response payload,"
                " but none was found.".format(self._legacy_client_config.legacy_auth_endpoint()),
                raw_response=response,
            )
        return json_response

    @staticmethod
    def _parse_json_response(response, json_response):
        token_jwt = json_response.get("token")
        if not token_jwt:
            raise PlanetLegacyAuthClientException(
                message='Authorization response did not include expected field "token"', raw_response=response
            )

        # The token is signed with a symmetric key.  The client does not
        # possess this key, and cannot verify the JWT.
        decoded_jwt = jwt.decode(token_jwt, options={"verify_signature": False})  # nosemgrep
        api_key = decoded_jwt.get("api_key")
        if not api_key:
            raise PlanetLegacyAuthClientException(
                message='Authorization response did not include expected field "api_key" in the returned token',
                raw_response=response,
            )

        return api_key, token_jwt

    def _checked_auth_request(self, auth_data):
        # Optimized for client use. We don't use a Session to pool connection
        # use at this time.
        response = self._session.post(
            self._legacy_client_config.legacy_auth_endpoint(),
            json=auth_data,
            headers={X_PLANET_APP_HEADER: X_PLANET_APP},
        )
        self._check_http_error(response)
        json_response = self._check_json_payload(response)
        return self._parse_json_response(response, json_response)

    def login(
        self,
        allow_open_browser: Optional[bool] = False,
        allow_tty_prompt: Optional[bool] = False,
        username: str = None,
        password: str = None,
        **kwargs,
    ) -> FileBackedPlanetLegacyApiKey:
        """
        Perform a login using Planet Legacy authentication endpoints.
        Parameters:
            username: Planet account user name. If not specified,
                the user will be prompted for their user name.
            password: Planet user password.  If not specified, the user
                will be prompted for their password.
            allow_tty_prompt: specify whether login is permitted to request
                input from the terminal.
        Returns:
            Upon successful login, a Credential will be returned. The returned
                value will be in memory only. It is the responsibility of the
                application to save this credential to disk as appropriate using
                the mechanisms built into the Credential type.
        """
        # TODO: should we warn if someone is doing a login when a static key has been
        #       configured in the client config (as opposed to having been saved
        #       in a credential file as the result of a login)?
        if not username:
            if allow_tty_prompt:
                username = input("Email: ")
            else:
                raise PlanetLegacyAuthClientException(
                    message="Username must be provided when performing non-interactive login"
                )

        if not password:
            if allow_tty_prompt:
                password = getpass.getpass(prompt="Password: ")
            else:
                raise PlanetLegacyAuthClientException(
                    message="Password must be provided when performing non-interactive login"
                )

        auth_payload = self._prepare_auth_payload(username, password)
        api_key, returned_jwt = self._checked_auth_request(auth_payload)
        return FileBackedPlanetLegacyApiKey(api_key=api_key, jwt=returned_jwt)

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> CredentialRequestAuthenticator:
        # If an API key has been configured in the client config, use that and ignore
        # any separate credential file.
        storage_provider = self._auth_client_config.storage_provider()
        if self._legacy_client_config.api_key():
            _credential = FileBackedPlanetLegacyApiKey(
                api_key=self._legacy_client_config.api_key(),
                api_key_file=self._legacy_client_config.path(),
                storage_provider=storage_provider,
            )
        else:
            if isinstance(credential, pathlib.Path):
                _credential = FileBackedPlanetLegacyApiKey(api_key_file=credential, storage_provider=storage_provider)
            elif isinstance(credential, FileBackedPlanetLegacyApiKey):
                _credential = credential
            elif credential is None:
                # This will be brain-dead until update_credential() or update_credential_data()
                # is called.  This is useful for initializing properly typed credential objects.
                _credential = FileBackedPlanetLegacyApiKey(storage_provider=storage_provider)
            else:
                raise TypeError(
                    f"{type(self).__name__} does not support {type(credential)} credentials.  Use file path or FileBackedPlanetLegacyApiKey."
                )

        return PlanetLegacyRequestAuthenticator(planet_legacy_credential=_credential)

    def can_login_unattended(self) -> bool:
        # We could allow username/password to be specified in the client
        # config, and forgo prompts in login(), but we've not implemented
        # what would be a bad security practice of saving passwords.
        return False
