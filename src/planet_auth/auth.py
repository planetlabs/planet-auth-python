# Copyright 2024 Planet Labs PBC.
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
from planet_auth.auth_exception import AuthException
from planet_auth.credential import Credential
from planet_auth.request_authenticator import CredentialRequestAuthenticator


class AuthClientContextException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


# TODO: should this be renamed? AuthClientContext? ClientAuthContext? ClientAuth?
#       This isn't really geared towards resource server use cases.
class Auth:
    """
    A container class for initializing and managing a working set of
    authentication objects.  See factory methods for user friendly initialization.
    This container class is geared toward client use cases - that is,
    authenticating ourselves as a client with the goal of
    making authenticated network API calls.
    """

    # TODO: since profiles have been moved out of the core lib,
    #  profile_name doesn't make a lot of sense anymore.
    def __init__(
        self,
        auth_client: AuthClient,
        request_authenticator: CredentialRequestAuthenticator,
        token_file_path: Optional[pathlib.Path] = None,
        profile_name: Optional[str] = None,
    ):
        """
        Create a new auth container object with the specified auth components.
        Users should generally use one of the more friendly static initializer methods.
        """
        self._auth_client = auth_client
        self._request_authenticator = request_authenticator
        self._token_file_path = token_file_path
        self._profile_name = profile_name
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

    def login(self, **kwargs) -> Credential:
        """
        Perform a login with the configured auth client.
        This higher level function will ensure that the token is saved
        to storage if Auth context has been configured with a
        suitable token file path.
        Otherwise, the token will be held only in memory.
        In all cases, the request authenticator will also be
        updated with the new credentials.
        """
        new_credential = self._auth_client.login(**kwargs)
        new_credential.set_path(self._token_file_path)
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
        This call will perform all of the same actions as `login()`.
        """
        new_credential = self._auth_client.device_login_complete(initiated_login_data)
        new_credential.set_path(self._token_file_path)
        new_credential.save()
        self._request_authenticator.update_credential(new_credential)
        return new_credential

    # def refresh(self, **kwargs):
    #     pass

    @staticmethod
    def initialize_from_client(
        auth_client: AuthClient,
        token_file: Optional[Union[str, pathlib.PurePath]] = None,
        profile_name: Optional[str] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            auth_client: An already constructed [AuthClient][planet_auth.AuthClient]
                object.
            token_file: A path to a file location that should be used for
                credential storage. Credentials will be read from this file,
                and this location may be used to save refreshed credentials.
                Depending on the configuration, this may possibly be
                ignored or may be None. When this is set to None,
                tokens will not be persisted on disk.
            profile_name: A profile name used to identify the Auth configration
                at runtime. This is not used to determine the location of
                configuration files or where to save tokens.
        """
        if token_file:
            token_file_path = pathlib.Path(token_file)
        else:
            token_file_path = None

        # TODO: I think I have some type checking and in-memory operations clean-up
        #   to do around credential being None.  I may need a way to contract an
        #   an auth context with a Credential object, or a path to obtaining
        #   one during operations.  In memory operations for the underlying Authenticators
        #   and AuthClients was largely done before this Auth class was created to
        #   provide a more convent top level manager, and this use case I think slipped by.
        request_authenticator = auth_client.default_request_authenticator(credential=token_file_path)  # type: ignore

        return Auth(
            auth_client=auth_client,
            request_authenticator=request_authenticator,
            token_file_path=token_file_path,
            profile_name=profile_name,
        )

    @staticmethod
    def initialize_from_config(
        client_config: AuthClientConfig,
        token_file: Optional[Union[str, pathlib.PurePath]] = None,
        profile_name: Optional[str] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            client_config: A constructed AuthClientConfig object.
            token_file: A path to a file location that should be used for
                credential storage. Credentials will be read from this file,
                and this location may be used to save refreshed credentials.
                Depending on the configuration, this may possibly be
                ignored or may be None. When this is set to None,
                tokens will not be persisted on disk.
            profile_name: A profile name used to identify the Auth configration
                at runtime. This is not used to determine the location of
                configuration files or where to save tokens.
        """
        auth_client = AuthClient.from_config(config=client_config)
        return Auth.initialize_from_client(auth_client=auth_client, token_file=token_file, profile_name=profile_name)

    @staticmethod
    def initialize_from_config_dict(
        client_config: dict,
        token_file: Optional[Union[str, pathlib.PurePath]] = None,
        profile_name: Optional[str] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            client_config: A dictionary containing a valid auth client configuration.
            token_file: A path to a file location that should be used for
                credential storage. Credentials will be read from this file,
                and this location may be used to save refreshed credentials.
                Depending on the configuration, this may possibly be
                ignored or may be None. When this is set to None,
                tokens will not be persisted on disk.
            profile_name: A profile name used to identify the Auth configration
                at runtime. This is not used to determine the location of
                configuration files or where to save tokens.
        """
        auth_client_config = AuthClientConfig.from_dict(client_config)
        return Auth.initialize_from_config(
            client_config=auth_client_config, token_file=token_file, profile_name=profile_name
        )

    @staticmethod
    def initialize_from_config_file(
        client_config_file: Union[str, pathlib.PurePath],
        token_file: Union[str, pathlib.PurePath] = None,
        profile_name: Optional[str] = None,
    ) -> Auth:
        """
        Construct and initialize a working set of authentication primitives,
        returning them in a new container object.
        Parameters:
            client_config_file: A file containing a client config json definition.
                The file should be a .json or .sops.json file
            token_file: A path to a file location that should be used for
                credential storage. Credentials will be read from this file,
                and this location may be used to save refreshed credentials.
                Depending on the configuration, this may possibly be
                ignored or may be None.  When this is set to None,
                tokens will not be persisted on disk.
            profile_name: A profile name used to identify the Auth configration
                at runtime. This is not used to determine the location of
                configuration files or where to save tokens.
        """
        auth_client_config = AuthClientConfig.from_file(client_config_file)
        return Auth.initialize_from_config(
            client_config=auth_client_config, token_file=token_file, profile_name=profile_name
        )