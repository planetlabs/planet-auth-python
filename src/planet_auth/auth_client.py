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

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Union
import pathlib

import planet_auth.logging.auth_logger
from planet_auth.auth_exception import AuthException
from planet_auth.credential import Credential
from planet_auth.request_authenticator import CredentialRequestAuthenticator
from planet_auth.storage_utils import InvalidDataException, ObjectStorageProvider, FileBackedJsonObject

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class AuthClientException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class AuthClientConfigException(InvalidDataException):  # Audit
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class AuthClientConfig(FileBackedJsonObject, ABC):
    """
    Base class for auth client configuration objects. Each concrete auth
    client type has a dedicated auth client config type to provide
    client specific validation and guardrails.

    The factory methods in the base class accept a dictionary, and will
    return an instance of an appropriate subclass.
    """

    _typename_map: Dict[str, AuthClientConfig] = {}
    _config_types: List[AuthClientConfig] = []
    # TODO: Constants for other keys? Most config dictionary keys belong to
    #       child classes, not us. We would also have to distinguish meta keys
    #       from config dictionary keys. Most meta keys are not for the
    #       AuthClient itself, but helpers that may exist in other class
    #       hierarchies.
    CLIENT_TYPE_KEY = "client_type"

    def __init__(self, file_path=None, storage_provider: Optional[ObjectStorageProvider] = None, **kwargs):
        super().__init__(data=kwargs, file_path=file_path, storage_provider=storage_provider)
        if len(kwargs.keys()) > 0:
            # raise AuthClientConfigException(
            # message='Unexpected config arguments in client configuration: {}'
            # .format(', '.join(kwargs.keys())))
            for key in kwargs.keys():
                if key != AuthClientConfig.CLIENT_TYPE_KEY:
                    auth_logger.debug(msg='Ignoring unknown keyword argument: "{}"'.format(str(key)))
                    # TODO? We now have the option of shoving these into self._data
                    # This will impact how we save/copy data

    @classmethod
    def _get_config_types(cls):
        if not cls._config_types:
            from planet_auth.oidc.auth_clients.client_validator import OidcClientValidatorAuthClientConfig
            from planet_auth.oidc.auth_clients.auth_code_flow import (
                AuthCodeClientConfig,
                AuthCodeWithClientSecretClientConfig,
                AuthCodeWithPubKeyClientConfig,
            )
            from planet_auth.oidc.auth_clients.client_credentials_flow import (
                ClientCredentialsPubKeyClientConfig,
                ClientCredentialsClientSecretClientConfig,
            )
            from planet_auth.oidc.auth_clients.device_code_flow import (
                DeviceCodeClientConfig,
                DeviceCodeWithClientSecretClientConfig,
                DeviceCodeWithPubKeyClientConfig,
            )
            from planet_auth.oidc.auth_clients.resource_owner_flow import (
                ResourceOwnerClientConfig,
                ResourceOwnerWithClientSecretClientConfig,
                ResourceOwnerWithPubKeyClientConfig,
            )
            from planet_auth.planet_legacy.auth_client import PlanetLegacyAuthClientConfig
            from planet_auth.static_api_key.auth_client import StaticApiKeyAuthClientConfig
            from planet_auth.none.noop_auth import NoOpAuthClientConfig

            cls._config_types = [
                AuthCodeClientConfig,
                AuthCodeWithPubKeyClientConfig,
                AuthCodeWithClientSecretClientConfig,
                ClientCredentialsPubKeyClientConfig,
                ClientCredentialsClientSecretClientConfig,
                DeviceCodeClientConfig,
                DeviceCodeWithClientSecretClientConfig,
                DeviceCodeWithPubKeyClientConfig,
                ResourceOwnerClientConfig,
                ResourceOwnerWithPubKeyClientConfig,
                ResourceOwnerWithClientSecretClientConfig,
                OidcClientValidatorAuthClientConfig,
                PlanetLegacyAuthClientConfig,
                StaticApiKeyAuthClientConfig,
                NoOpAuthClientConfig,
            ]
        return cls._config_types

    @classmethod
    def _get_typename_map(cls):
        if not cls._typename_map:
            for conf_type in cls._get_config_types():
                cls._typename_map[conf_type.meta().get(cls.CLIENT_TYPE_KEY)] = conf_type
        return cls._typename_map

    @classmethod
    def from_dict(cls, config_data: Dict) -> AuthClientConfig:
        """
        Create a AuthClientConfig from a configuration dictionary.
        Returns:
            A concrete auth client config object.
        """
        if not config_data:
            raise AuthClientException(message="Error: Auth client config dictionary must not be empty or None")
        config_type = config_data.get(cls.CLIENT_TYPE_KEY)
        config_cls = AuthClientConfig._get_typename_map().get(config_type)
        if not config_cls:
            raise AuthClientException(
                message='Error: Auth client config type "{}" is not understood by the factory.'.format(config_type)
            )
        return config_cls(**config_data)

    @staticmethod
    def from_file(file_path, storage_provider: Optional[ObjectStorageProvider] = None) -> AuthClientConfig:
        """
        Create an AuthClientConfig from a json file that contains a config
        dictionary.
        Returns:
            A concrete auth client config object.
        """
        config_file = FileBackedJsonObject(file_path=file_path, storage_provider=storage_provider)
        config_file.load()
        # AuthClientConfig.from_dict() also returns a FileBackedJsonObject.
        # Re-creating with from_dict() after the load() gives us a more strongly
        # typed subclass with better data checking and better error messages.
        conf = AuthClientConfig.from_dict(config_file.data())
        conf.set_path(file_path)
        conf.set_storage_provider(storage_provider=storage_provider)
        return conf

    @classmethod
    @abstractmethod
    def meta(cls) -> Dict:
        """
        Return a dictionary of metadata.
        The meta dictionary provides a place to store information that is
        primarily for users of AuthClient types rather than for the operation
        of the Auth Client itself.

        Meta Keys:
            client_type: The literal value used for `client_type` in configuration
                dictionaries that indicates the selection of the AuthClient type.

            auth_client_class: The concrete `AuthClient` class that is served by
                the configuration type.

            display_name: Display name for the `AuthClient` type

            description: A description of the `AuthClient` type

            config_hints: A list configuration hints bootstrapping a configuration
                with a wizard of some sort.  This is distinct from a rigid schema for
                the configuration type.
        """


# TODO: Revisit this interface.  Since we've done some other refactoring,
#       it may not make sense for all of these to be on the AuthClient
#       base ABC. (Specifically, many of the OAuth specific methods,
#       perhaps others.)
class AuthClient(ABC):
    """
    Base class for auth clients.  Concrate instances of this base class
    manage the specific of how to authenticate a user and obtain credentials
    that may be used for service APIs.

    The factory methods in the base class accepts a client specific client
    configuration type, and will return an instance of an appropriate subclass.

    Example:
        ```python
        from planet_auth import AuthClientConfig, AuthClient
        config_dict = { ... } # See AuthClientConfig
        my_auth_config = AuthClientConfig.from_dict(config_dict)
        my_auth_client = AuthClient.from_config(my_auth_config)
        ```
    """

    _type_map: Dict[AuthClientConfig, AuthClient] = {}

    def __init__(self, auth_client_config: AuthClientConfig):
        auth_client_config.lazy_load()
        auth_client_config.check()  # Cowardly refuse to create clients with brain damaged configuration.
        self._auth_client_config = auth_client_config

    @classmethod
    def _get_type_map(cls):
        # pylint: disable=protected-access
        if not cls._type_map:
            for conf_type in AuthClientConfig._get_config_types():
                cls._type_map[conf_type] = conf_type.meta().get("auth_client_class")
        return cls._type_map

    @classmethod
    def from_config(cls, config: AuthClientConfig) -> AuthClient:
        """
        Create an AuthClient of an appropriate subtype from the client config.
        Returns:
            An initialized auth client instance.
        """
        client_cls = AuthClient._get_type_map().get(type(config))
        if not client_cls:
            raise AuthClientException(message="Error: Auth client config class is not understood by the factory.")

        return client_cls(config)

    def config(self) -> AuthClientConfig:
        return self._auth_client_config

    @abstractmethod
    def login(
        self, allow_open_browser: Optional[bool] = False, allow_tty_prompt: Optional[bool] = False, **kwargs
    ) -> Credential:
        """
        Perform an initial login using the authentication mechanism
        implemented by the AuthClient instance.  The results of a successful
        login is FileBackedJsonObject Credential containing credentials that
        may be used for subsequent service API requests.  How these
        credentials are used for this purpose is outside the scope of either
        the AuthClient or the Credential.  This is the job of a
        RequestAuthenticator.

        The login command is permitted to be user interactive.  Depending on
        the implementation, this may include terminal prompts, or may require the
        use of a web browser.

        Authentication parameters are specific to each implementation. Consult
        subclass documentation for details.

        Parameters:
            allow_open_browser: specify whether login is permitted to open
                a browser window.
            allow_tty_prompt: specify whether login is permitted to request
                input from the terminal.
        Returns:
            Upon successful login, a Credential will be returned. The returned
                value will be in memory only. It is the responsibility of the
                application to save this credential to disk as appropriate using
                the mechanisms built into the Credential type.  AuthClient
                implementations should raise an exception for all login errors.
        """

    def device_login_initiate(self, **kwargs) -> Dict:
        """
        Initiate the process to login a device with limited UI capabilities.
        The returned dictionary should contain information for the application
        to present to the user, allowing the user to complete the login process
        asynchronously.

        After prompting the user, `device_login_complete()` should be called
        with the same dictionary that was returned by this call.

        Returns:
            Upon successful initiation of an asynchronous device login process,
                a dictionary containing information that must be presented
                to the user will be returned.
        """
        raise AuthClientException(message="Device login is not supported for the current authentication mechanism")

    def device_login_complete(self, initiated_login_data: Dict) -> Credential:
        """
        Complete a login process that was initiated by a call to `device_login_initiate()`.

        Parameters:
            initiated_login_data: The dictionary that was returned by `device_login_initiate()`

        Returns:
            Upon successful login, a Credential will be returned. The returned
                value will be in memory only. It is the responsibility of the
                application to save this credential to disk as appropriate using
                the mechanisms built into the Credential type.
        """
        raise AuthClientException(message="Device login is not supported for the current authentication mechanism")

    def refresh(self, refresh_token: str, requested_scopes: List[str]) -> Credential:
        # TODO: It may be better to accept a Credential as input?
        """
        Obtain a refreshed credential using the supplied refresh token.
        This method will be implemented by concrete AuthClients that
        implement a particular OAuth flow.
        Parameters:
            refresh_token: Refresh token
            requested_scopes: Scopes to request in the access token
        Returns:
            Upon success, a fresh Credential will be returned. As with
                login(), this credential will not have been persisted to storage.
                This is the responsibility of the application.
                AuthClient implementations should raise an exception for all login
                errors.
        """
        raise AuthClientException(message="Refresh not implemented for the current authentication mechanism")

    def validate_access_token_remote(self, access_token: str) -> Dict:
        """
        Validate an access token with the authorization server.
        Parameters:
            access_token: Access token to validate
        Returns:
            Returns a dictionary of validated token claims. It should be
                noted that the returned dictionaries from local and service
                token validation are not exactly the same.  Service validation
                should return a RFC 7662 dictionary.  Local validation returns
                the token claims.
        """
        raise AuthClientException(
            message="Access token validation is not implemented for the current authentication mechanism"
        )

    def validate_access_token_local(
        self, access_token: str, required_audience: str = None, scopes_anyof: list = None
    ) -> Dict:
        """
        Validate an access token locally. While the validation is local,
        the authorization server may still may contacted to obtain signing
        keys for validation.  Signing keys will be cached for future use.

        Auth servers (issuers) may provide service for any number of audiences,
        so which audience is expected / required is potentially different
        for each discrete validation check.  If the required audience
        is not provided as an argument, the validate should fall back
        to the audiences configured in the AuthClientConfig.

        If the audience is neither provided as an argument nor present in
        the AuthClientConfig, an error should be raised.

        Note:
            While tokens may have multiple audiences, and AuthClients
            may be configured to request multiple audiences,
            the validation method currently only supports checking for
            a single audience. This could be considered is a bit of an
            API mismatch. However, at this time this is considered expected
            and desirable behavior. Validation is generally considered to
            be occurring in a context that self identifies as a particular
            audience, and overlapping claims may mean different things
            to different audiences.  Validation should be done in the
            context of a single audience at a time.

        Parameters:
            access_token: Access token to validate.
            required_audience: Audience that the token is required to have.
            scopes_anyof: Optional list of OAuth2 scopes to check for in the token.
                This list is an "any of" list of scopes. As long as one of the scopes in the
                list is present, validation will pass. If none of the scopes are present,
                validation will fail.
        Returns:
            Returns a dictionary of validated token claims. It should be
                noted that the returned dictionaries from local and service
                token validation are not exactly the same.  Service validation
                should return a RFC 7662 dictionary.  Local validation returns
                the token claims.
        """
        raise AuthClientException(
            message="Access token validation is not implemented for the current authentication mechanism"
        )

    def validate_id_token_remote(self, id_token: str) -> Dict:
        """
        Validate an ID token with the authorization server.
        Parameters:
            id_token: ID token to validate
        Returns:
            Returns a dictionary of validated token claims
        """
        raise AuthClientException(
            message="ID token validation is not implemented for the current authentication mechanism"
        )

    def validate_id_token_local(self, id_token: str) -> Dict:
        """
        Validate an ID token locally. The authorization server may still be
        called to obtain signing keys for validation.  Signing keys will be
        cached for future use.
        Parameters:
            id_token: ID token to validate
        Returns:
            Returns a dictionary of validated token claims
        """
        raise AuthClientException(
            message="ID token validation is not implemented for the current authentication mechanism"
        )

    def validate_refresh_token_remote(self, refresh_token: str) -> Dict:
        """
        Validate a refresh token with the authorization server.
        Parameters:
            refresh_token: Refresh token to validate
        Returns:
            Returns the response from the remove validation service.
        """
        raise AuthClientException(
            message="Refresh token validation is not implemented for the current authentication mechanism"
        )

    def revoke_access_token(self, access_token: str):
        """
        Revoke an access token with the authorization server.
        Parameters:
            access_token: Access token to revoke.
        """
        raise AuthClientException(
            message="Access token revocation is not implemented for the current authentication mechanism"
        )

    def revoke_refresh_token(self, refresh_token: str):
        """
        Revoke a refresh token with the authorization server.
        Parameters:
            refresh_token: Access token to revoke.
        """
        raise AuthClientException(
            message="Refresh token revocation is not implemented for the current authentication mechanism"
        )

    def userinfo_from_access_token(self, access_token: str) -> Dict:
        """
        Look up user information from the auth server using the access token.
        Parameters:
            access_token: User access token.
        """
        raise AuthClientException(
            message="User information lookup is not implemented for the current authentication mechanism"
        )

    def oidc_discovery(self) -> Dict:
        """
        Query the authorization server's OIDC discovery endpoint for server information.
        Returns:
            Returns the OIDC discovery dictionary.
        """
        raise AuthClientException(
            message="OIDC discovery is not implemented for the current authentication mechanism."
        )

    # def oauth_discovery(self) -> Dict:
    #     """
    #     Query the authorization server's OAuth2 discovery endpoint for server information.
    #     Returns:
    #         Returns the OAuth2 discovery dictionary.
    #     """
    #     raise AuthClientException(
    #         message="OAuth2 discovery is not implemented for the current authentication mechanism."
    #     )

    def get_scopes(self) -> List[str]:
        """
        Query the authorization server for a list of scopes.
        Returns:
            Returns a list of scopes that may be requested during a call
                to login or refresh
        """
        raise AuthClientException(
            message="Listing scopes is not implemented for the current authentication mechanism."
        )

    # TODO: as a practical matter, I don't think we ever use the "Credential"
    #   option, and it makes the code more clumsy.  We should consider removing it.
    @abstractmethod
    def default_request_authenticator(
        self,
        credential: Union[pathlib.Path, Credential],
    ) -> CredentialRequestAuthenticator:
        """
        Return an instance of the default request authenticator to use for
        the specific AuthClient type and configured to use the provided
        credential file for persistence.

        It's not automatic that the default is always the right choice.
        Some authenticators may initiate logins, which may be interactive
        or not depending on the specifics of the AuthClient configuration
        and implementation type. Whether or not interactivity can be
        tolerated depends on the specifics of the surrounding application.

        In the simplest cases, there really is no relationship between
        the AuthClient and the request authenticator (see static key
        implementations). This relationship emerges when the mechanisms
        of an AuthClient requires frequent refreshing of the Credential.
        In these cases, it is convenient for the CredentialRequestAuthenticator
        to also have an AuthClient that is capable of performing this
        refresh transparently as needed.

        AuthClient implementors should favor defaults that do not require
        user interaction after an initial Credential has been obtained from
        an initial call to login()

        Parameters:
            credential: A Credential object, or a Path to the credential
                file that can be used to create an appropriate credential
                object.
        Returns:
            Returns an instance of the default request authenticator class to
                use for Credentials of the type obtained by the AuthClient.
        """

    @abstractmethod
    def can_login_unattended(self) -> bool:
        """
        Check whether the client can perform an unattended login.

        Depending on the implementation, some clients may be able to perform
        unattended logins based on information the client config (e.g. static
        API key clients can do this).  These should return true.  Other clients
        will always require user interactive logins (e.g. a user interactive
        client using a browser and MFA to login).  These should return false.
        Some clients may be flexible and support either depending on the state
        of their configuration.  These should return a result based on their
        configuration.
        """
