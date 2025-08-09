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

from __future__ import annotations  # https://stackoverflow.com/a/33533514

import pathlib
from typing import Optional, Union

from planet_auth.auth_client import AuthClient, AuthClientConfig
from planet_auth.credential import Credential
from planet_auth.request_authenticator import CredentialRequestAuthenticator
from planet_auth.storage_utils import ObjectStorageProvider
from planet_auth.logging.auth_logger import getAuthLogger

auth_logger = getAuthLogger()

# class AuthClientContextException(AuthException):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)


class Auth:
    """
    A container class for initializing and managing a working set of
    authentication objects.  See factory methods and the
    `planet_auth_utils.PlanetAuthFactory` class for user-friendly
    initialization.

    This container class provides an "auth context" is geared toward client
    use cases - that is, authenticating ourselves as a client with the goal
    of making authenticated network API calls to resource servers.  Resource
    servers that have to validate incoming clients' credentials have some different
    concerns not handled here.
    """

    def __init__(
        self,
        auth_client: AuthClient,
        request_authenticator: CredentialRequestAuthenticator,
        token_file_path: Optional[pathlib.Path] = None,
        profile_name: Optional[str] = None,
    ):
        """
        Create a new auth container object with the specified auth components.
        Users should use one of the more friendly static initializer methods.
        """
        auth_logger.debug(
            msg=f"Initializing Auth Context. Profile: {profile_name} ; Type: {type(auth_client).__name__} ; Token file: {token_file_path}"
        )

        self._auth_client = auth_client
        self._request_authenticator = request_authenticator
        self._token_file_path = token_file_path
        self._profile_name = profile_name
        self._storage_provider = auth_client.config().storage_provider()
        # We do not store the credential since implementations are
        # free to change it out from underneath us during operation.
        # This is common with refresh tokens, for example.
        # self._credential = credential

    def auth_client(self) -> AuthClient:
        """
        Get the currently configured auth client.
        Returns:
            The current AuthClient instance.
        """
        return self._auth_client

    def request_authenticator(self) -> CredentialRequestAuthenticator:
        """
        Get the current request authenticator.
        Returns:
            The current CredentialRequestAuthenticator instance.
        """
        return self._request_authenticator

    def token_file_path(self) -> Optional[pathlib.Path]:
        """
        Get the path to the current credentials file.
        Returns:
            The path to the current credentials file.
        """
        return self._token_file_path

    def profile_name(self) -> Optional[str]:
        """
        Get the current profile name, if known. May be empty if initialization
        was performed without using a profile.
        Returns:
            Returns the name of the current profile, if known.
        """
        return self._profile_name

    def request_authenticator_is_ready(self) -> bool:
        """
        Check whether the current context's request_authenticator is ready
        for use.

        A context is considered initialized if it can be used to make
        authenticated client requests without user intervention.  What exactly
        that requires can vary by auth client configured in the context.
        For example, simple API key clients only need an API key in their
        configuration.  OAuth2 user clients need to have performed
        a user login and obtained access or refresh tokens.
        """
        return self._request_authenticator.is_initialized() or self._auth_client.can_login_unattended()

    def login(self, **kwargs) -> Credential:
        """
        Perform a login with the configured auth client.
        This higher level function will ensure that the token is saved to
        storage if Auth context has been configured with a suitable token
        storage path.  Otherwise, the token will be held only in memory.
        In all cases, the request authenticator will also be updated with
        the new credentials.
        """
        new_credential = self._auth_client.login(**kwargs)
        new_credential.set_path(self._token_file_path)
        new_credential.set_storage_provider(self._storage_provider)
        new_credential.save()
        self._request_authenticator.update_credential(new_credential)
        return new_credential

    def device_login_initiate(self, **kwargs) -> dict:
        """
        Initiate the process to login a device with limited UI capabilities.
        The returned dictionary should contain information for the application
        to present to the user, allowing the user to complete the login process
        asynchronously.

        After prompting the user, `device_login_complete()` should be called
        with the same dictionary that was returned by this call.
        """
        return self._auth_client.device_login_initiate(**kwargs)

    def device_login_complete(self, initiated_login_data: dict) -> Credential:
        """
        Complete a login process that was initiated by a call to `device_login_initiate()`.
        This call will perform all the same actions as `login()`.
        """
        new_credential = self._auth_client.device_login_complete(initiated_login_data)
        new_credential.set_path(self._token_file_path)
        new_credential.set_storage_provider(self._storage_provider)
        new_credential.save()
        self._request_authenticator.update_credential(new_credential)
        return new_credential

    # def refresh(self, **kwargs):
    #     pass

    @staticmethod
    def initialize_from_client(
        auth_client: AuthClient,
        initial_token_data: Optional[dict] = None,
        token_file: Optional[Union[str, pathlib.PurePath]] = None,
        profile_name: Optional[str] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            auth_client: An already constructed [AuthClient][planet_auth.AuthClient]
                object.
            initial_token_data: Token data to use for initial state, if not to be
                read from storage for initialization.
            token_file: A path to the storage location that should be used for
                credential storage. Credentials will be read from this location,
                and this location will be used to save refreshed credentials.
                Depending on the configuration, this may be
                ignored or may be None. When this is set to None,
                tokens will not be persisted to storage.
            profile_name: A profile name used to identify the Auth configration
                at runtime.
        """
        if token_file:
            token_file_path = pathlib.Path(token_file)
        else:
            token_file_path = None

        request_authenticator = auth_client.default_request_authenticator(credential=token_file_path)  # type: ignore
        if initial_token_data:
            request_authenticator.update_credential_data(initial_token_data)
        return Auth(
            auth_client=auth_client,
            request_authenticator=request_authenticator,
            token_file_path=token_file_path,
            profile_name=profile_name,
        )

    @staticmethod
    def initialize_from_config(
        client_config: AuthClientConfig,
        initial_token_data: Optional[dict] = None,
        token_file: Optional[Union[str, pathlib.PurePath]] = None,
        profile_name: Optional[str] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            client_config: A constructed AuthClientConfig object.
            initial_token_data: Token data to use for initial state, if not to be
                read from storage for initialization.
            token_file: A path to the storage location that should be used for
                credential storage. Credentials will be read from this location,
                and this location will be used to save refreshed credentials.
                Depending on the configuration, this may be
                ignored or may be None. When this is set to None,
                tokens will not be persisted to storage.
            profile_name: A profile name used to identify the Auth configration
                at runtime.
        """
        auth_client = AuthClient.from_config(config=client_config)
        return Auth.initialize_from_client(
            auth_client=auth_client,
            initial_token_data=initial_token_data,
            token_file=token_file,
            profile_name=profile_name,
        )

    @staticmethod
    def initialize_from_config_dict(
        client_config: dict,
        initial_token_data: Optional[dict] = None,
        token_file: Optional[Union[str, pathlib.PurePath]] = None,
        profile_name: Optional[str] = None,
        storage_provider: Optional[ObjectStorageProvider] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            client_config: A dictionary containing a valid auth client configuration.
            initial_token_data: Token data to use for initial state, if not to be
                read from storage for initialization.
            token_file: A path to a storage location that should be used for
                credential storage. Credentials will be read from this location,
                and this location may be used to save refreshed credentials.
                Depending on the configuration, this may be
                ignored or may be None. When this is set to None,
                tokens will not be persisted to storage.
            profile_name: A profile name used to identify the Auth configration
                at runtime.
            storage_provider: A custom storage provider to use.
        """
        auth_client_config = AuthClientConfig.from_dict(config_data=client_config)
        if storage_provider:
            auth_client_config.set_storage_provider(storage_provider=storage_provider)
        return Auth.initialize_from_config(
            client_config=auth_client_config,
            initial_token_data=initial_token_data,
            token_file=token_file,
            profile_name=profile_name,
        )
