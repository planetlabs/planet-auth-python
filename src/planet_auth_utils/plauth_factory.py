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

import warnings

from typing import List, Optional, Tuple

from planet_auth import (
    Auth,
    AuthClientConfig,
    AuthException,
    ObjectStorageProvider,
    OidcMultiIssuerValidator,
    PlanetLegacyRequestAuthenticator,
)
from planet_auth.constants import (
    TOKEN_FILE_SOPS,
    TOKEN_FILE_PLAIN,
    AUTH_CONFIG_FILE_SOPS,
    AUTH_CONFIG_FILE_PLAIN,
)

from planet_auth_utils.profile import Profile
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfigEnhanced
from planet_auth_utils.constants import EnvironmentVariables
from planet_auth.logging.auth_logger import getAuthLogger

auth_logger = getAuthLogger()
_PL_API_KEY_ADHOC_PROFILE_NAME = "_PL_API_KEY"


class PlanetAuthFactory:
    @staticmethod
    def _token_file_path(profile_name: str, overide_path: Optional[str], save_token_file: bool):
        # The initialized Auth object just uses whether or not a token file path
        # is set to determine whether to use a credential file.  The layering from
        # the sources of config values needs some handholding
        # to set the token file value correctly to account for this.
        if save_token_file:
            return Profile.get_profile_file_path_with_priority(
                filenames=[TOKEN_FILE_SOPS, TOKEN_FILE_PLAIN], profile=profile_name, override_path=overide_path
            )
        else:
            return None

    @staticmethod
    def _auth_client_config_file_path(profile_name: str):
        return Profile.get_profile_file_path_with_priority(
            filenames=[AUTH_CONFIG_FILE_SOPS, AUTH_CONFIG_FILE_PLAIN], profile=profile_name
        )

    @staticmethod
    def _update_saved_profile_config(plauth_context: Auth, storage_provider: Optional[ObjectStorageProvider] = None):
        _profile_name = plauth_context.profile_name()
        if not _profile_name:
            raise MissingArgumentException("A profile name must be provided if persisting the profile configuration")

        plauth_context._auth_client.config().set_path(
            PlanetAuthFactory._auth_client_config_file_path(profile_name=_profile_name)
        )
        plauth_context._auth_client.config().set_storage_provider(storage_provider=storage_provider)
        plauth_context._auth_client.config().save()

    @staticmethod
    def load_auth_client_config_from_profile(
        profile_name: str,
        # storage_provider: Optional[ObjectStorageProvider] = None,  # not yet supported here.
    ) -> Tuple[str, AuthClientConfig]:
        """
        Load the auth client config from a profile name.  Both built-in and used defined
        custom profiles are considered.
        """
        # TODO: does not yet support custom storage providers
        if Builtins.is_builtin_profile(profile_name):
            normalized_profile_name = Builtins.dealias_builtin_profile(profile_name)
            auth_client_config = Builtins.load_builtin_auth_client_config(normalized_profile_name)
        else:
            normalized_profile_name = profile_name.lower()
            auth_client_config = Profile.load_auth_client_config(
                profile=normalized_profile_name,
                # storage_provider=storage_provider,
            )

        return normalized_profile_name, auth_client_config

    @staticmethod
    def _init_context_from_profile(
        profile_name: str,
        token_file_opt: Optional[str] = None,
        save_token_file: bool = True,
        # storage_provider: Optional[ObjectStorageProvider] = None,  # not yet supported here.
    ) -> Auth:
        normalized_selected_profile, auth_client_config = PlanetAuthFactory.load_auth_client_config_from_profile(
            profile_name=profile_name,
            # storage_provider=storage_provider,
        )

        token_file_path = PlanetAuthFactory._token_file_path(
            profile_name=normalized_selected_profile, overide_path=token_file_opt, save_token_file=save_token_file  # type: ignore
        )

        auth_logger.debug(msg=f"Initializing Auth from profile {normalized_selected_profile}")
        return Auth.initialize_from_config(
            client_config=auth_client_config,
            token_file=token_file_path,
            profile_name=normalized_selected_profile,
        )

    @staticmethod
    def _init_context_from_oauth_svc_account(
        client_id: str,
        client_secret: str,
        token_file_opt: Optional[str] = None,
        save_token_file: bool = True,
        # profile_name: Optional[str] = None, # TODO? Always currently ad-hoc with this initializer's use.
        save_profile_config: bool = False,
        # storage_provider: Optional[ObjectStorageProvider] = None,  # not yet supported here.
    ) -> Auth:
        # TODO: support oauth service accounts that use pubkey, and not just client secrets.
        # TODO: Can we handle different trust realms when initializing a M2M client with
        #       just the Client ID and secret? (akin to how Auth0 implements AUTH0_DOMAIN usage.)
        m2m_realm_name = Builtins.builtin_default_profile_name(client_type="oidc_client_credentials_secret")
        base_client_config = Builtins.builtin_profile_auth_client_config_dict(m2m_realm_name)
        constructed_client_config_dict = {
            **base_client_config,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        adhoc_profile_name = f"{m2m_realm_name}-{client_id}"

        token_file_path = PlanetAuthFactory._token_file_path(
            profile_name=adhoc_profile_name, overide_path=token_file_opt, save_token_file=save_token_file
        )

        auth_logger.debug(msg=f"Initializing Auth for service account {m2m_realm_name}:{client_id}")
        plauth_context = Auth.initialize_from_config_dict(
            client_config=constructed_client_config_dict,
            token_file=token_file_path,
            profile_name=adhoc_profile_name,
        )
        if save_profile_config:
            PlanetAuthFactory._update_saved_profile_config(
                plauth_context=plauth_context,
                # storage_provider=storage_provider,  # Not yet supported here
            )

        return plauth_context

    @staticmethod
    def _init_context_from_client_config(
        client_config: dict,
        profile_name: str,
        initial_token_data: Optional[dict] = None,
        save_token_file: bool = True,
        save_profile_config: bool = True,
        storage_provider: Optional[ObjectStorageProvider] = None,
    ) -> Auth:
        token_file_path = PlanetAuthFactory._token_file_path(
            profile_name=profile_name, overide_path=None, save_token_file=save_token_file
        )

        auth_logger.debug(msg="Initializing Auth from provided configuration")
        plauth_context = Auth.initialize_from_config_dict(
            client_config=client_config,
            initial_token_data=initial_token_data,
            token_file=token_file_path,
            profile_name=profile_name,
            storage_provider=storage_provider,
        )
        if save_profile_config:
            PlanetAuthFactory._update_saved_profile_config(
                plauth_context=plauth_context, storage_provider=storage_provider
            )

        return plauth_context

    # @staticmethod
    # def _init_context_from_legacy_username_password_key(
    #     username: str,
    #     password: str,
    #     token_file_opt: Optional[str] = None,
    #     save_token_file: bool = True,
    # ) -> Auth:
    #     pass
    ## Purposefully not supporting this at this time.
    ## This would be a good place to make use of a built-in legacy type profile.

    @staticmethod
    def _init_context_from_api_key(api_key: str) -> Auth:
        ## We used to use built-in profiles that knew the legacy protocol.
        ## But, since that AuthClient largely exists to turn username/password into
        ## API keys (or legacy JWTs), we can bypass it and simply use an API key AuthClient.
        ## This is desirable since we do not have to know about authentication endpoints.
        # selected_profile_name = Builtins.BUILTIN_PROFILE_NAME_LEGACY
        # constructed_client_config_dict = Builtins._builtin.builtin_client_authclient_config_dicts()[
        #     selected_profile_name]
        # token_file_path = None  # Always None in this case. See _token_file_path() above.
        # constructed_client_config_dict["api_key"] = api_key
        # return Auth.initialize_from_config_dict(
        #    client_config=constructed_client_config_dict,
        #    token_file=token_file_path,
        #    profile_name=selected_profile_name,
        # )
        constructed_client_config_dict = {
            "client_type": "static_apikey",
            "api_key": api_key,
            "bearer_token_prefix": PlanetLegacyRequestAuthenticator.TOKEN_PREFIX,
        }
        adhoc_profile_name = _PL_API_KEY_ADHOC_PROFILE_NAME
        auth_logger.debug(msg="Initializing Auth from API key")
        plauth_context = Auth.initialize_from_config_dict(
            client_config=constructed_client_config_dict,
            token_file=None,
            profile_name=adhoc_profile_name,
        )

        # if save_profile_config:
        #    PlanetAuthFactory._update_saved_profile_config(
        #        plauth_context=plauth_context,
        #        storage_provider=storage_provider)

        return plauth_context

    @staticmethod
    def initialize_auth_client_context(
        auth_profile_opt: Optional[str] = None,
        auth_client_id_opt: Optional[str] = None,
        auth_client_secret_opt: Optional[str] = None,
        auth_api_key_opt: Optional[str] = None,  # Deprecated
        token_file_opt: Optional[str] = None,  # TODO: Remove? but we still depend on it for Planet Legacy use cases.
        # TODO?: initial_token_data: dict = None,
        save_token_file: bool = True,
        save_profile_config: bool = False,
        use_env: bool = True,
        use_configfile: bool = True,
        # Not supporting custom storage providers at this time.
        # The preferred behavior of Profiles with custom storage providers is TBD.
        # storage_provider: Optional[ObjectStorageProvider] = None,
    ) -> Auth:
        """
        Helper function to initialize the Auth context in applications.

        Between built-in profiles to interactively login users, customer or third party
        registered OAuth clients and corresponding custom profiles that may be saved on disk,
        OAuth service account profiles, and static API keys, there are a number of
        ways to configure how an application built with this library should authenticate
        requests made to the service.  Add to this configration may come from explict
        parameters set by the user, environment variables, configuration files, or values
        hard-coded by the application developer, and the number of possibilities rises.

        This helper function is provided to help build applications with a consistent
        user experience when sharing auth context with the CLI.  This function
        does not support using custom storage providers at this time.

        Arguments to this function are taken to be explicitly set by the user or
        application developer, and are given the highest priority.  Internally, the
        priority used for the source of any particular configuration values is, from
        highest to lowest priority, as follows:

        - Arguments to this function.
        - Environment variables.
        - Values from configuration file.
        - Built-in defaults.

        In constructing the returned Auth context, the following priority is applied, from
        highest to lowest:

        - A user selected auth profile, as specified by `auth_profile_opt`. This may either
          specify a built-in profile name, or a fully custom profile defined by files in
          a `~/.planet/<profile name>` directory.
        - A user selected OAuth service account, as specified by `auth_client_id_opt` and `auth_client_secret_opt`.
        - A user specified API key, as specified by `auth_api_key_opt`
        - A user selected auth profile, as determined from either environment variables or config files.
        - A user selected OAuth service account, as determined from either environment variables or config files.
        - A user selected API key, as determined from either environment variables or config files.
        - A built-in default auth profile, which may require interactive user authentication.

        Example:
            ```python
            @click.group(help="my cli main help message")
            @opt_auth_profile()
            @opt_auth_client_id()
            @opt_auth_client_secret()
            @click.pass_context
            def my_cli_main(ctx, auth_profile, auth_client_id, auth_client_secret):
                ctx.ensure_object(dict)
                ctx.obj["AUTH"] = PlanetAuthFactory.initialize_auth_client_context(
                    auth_profile_opt=auth_profile, auth_client_id_opt=auth_client_id, auth_client_secret_opt=auth_client_secret
                )
                # Click program may now use the auth context in all commands...
            ```

        Parameters:
            auth_profile_opt: The name of a built-in or custom profile to use for authentication.
                This option should reflect the explict choice of the user or application developer.
            auth_client_id_opt: The client ID of a registered OAuth client to use for authentication.
                This option should reflect the explict choice of the user or application developer.
            auth_client_secret_opt: The client secret of a registered OAuth client to use for authentication.
                This option should reflect the explict choice of the user or application developer.
            auth_api_key_opt: The API key to use for authentication. Deprecated.
                This option should reflect the explict choice of the user or application developer.
            token_file_opt: The path to a file to store the access token.
                This options should not generally be used, and may be removed in the future.
            save_token_file: Whether to save the access token to disk.  If `False`, in-memory
                operation will be used, and login sessions will not be persisted locally.
            save_profile_config: Whether to save the profile configuration to disk.
            use_env: Whether to use environment variables to determine configuration values.
            use_configfile: Whether to use configuration files to determine configuration values.
        """
        #
        # Initialize from explicit user selected options
        #
        if auth_profile_opt:
            return PlanetAuthFactory._init_context_from_profile(
                profile_name=auth_profile_opt,
                token_file_opt=token_file_opt,
                save_token_file=save_token_file,
            )

        if auth_client_id_opt and auth_client_secret_opt:
            return PlanetAuthFactory._init_context_from_oauth_svc_account(
                client_id=auth_client_id_opt,
                client_secret=auth_client_secret_opt,
                token_file_opt=token_file_opt,
                save_token_file=save_token_file,
                # profile_name="",  # Always ad-hoc in this path
                save_profile_config=save_profile_config,
            )

        if auth_api_key_opt:
            return PlanetAuthFactory._init_context_from_api_key(
                api_key=auth_api_key_opt,
            )

        #
        # Initialize from implicit user selected options (env and config files)
        #
        user_config_file = PlanetAuthUserConfigEnhanced()
        log_fallback_warning = False
        effective_user_selected_profile = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_PROFILE,
            override_value=auth_profile_opt,
            use_env=use_env,
            use_configfile=use_configfile,
        )
        if effective_user_selected_profile:
            try:
                return PlanetAuthFactory._init_context_from_profile(
                    profile_name=effective_user_selected_profile,
                    token_file_opt=token_file_opt,
                    save_token_file=save_token_file,
                )
            except Exception as e:
                auth_logger.warning(
                    msg=f'Unable to initialize user selected profile "{effective_user_selected_profile}".'
                    f' Profile was selected from {EnvironmentVariables.AUTH_PROFILE} environment variable or "{user_config_file.path()}" configuration file.'
                    f" Error: {e}"
                )
                log_fallback_warning = True

        effective_user_selected_client_id = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_CLIENT_ID,
            override_value=auth_client_id_opt,
            use_env=use_env,
            use_configfile=use_configfile,
        )
        effective_user_selected_client_secret = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_CLIENT_SECRET,
            override_value=auth_client_secret_opt,
            use_env=use_env,
            use_configfile=use_configfile,
        )
        if effective_user_selected_client_id and effective_user_selected_client_secret:
            return PlanetAuthFactory._init_context_from_oauth_svc_account(
                client_id=effective_user_selected_client_id,
                client_secret=effective_user_selected_client_secret,
                token_file_opt=token_file_opt,
                save_token_file=save_token_file,
                # profile_name="",  # Always ad-hoc in this path
                save_profile_config=save_profile_config,
            )

        effective_user_selected_api_key = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_API_KEY,
            override_value=auth_api_key_opt,
            use_env=use_env,
            use_configfile=use_configfile,
        )
        if effective_user_selected_api_key:
            return PlanetAuthFactory._init_context_from_api_key(
                api_key=effective_user_selected_api_key,
            )

        effective_user_selected_api_key = user_config_file.effective_conf_value(
            config_key="key",  # For backwards compatibility, we know the old SDK used this in json files.
            override_value=auth_api_key_opt,
            use_env=False,
            use_configfile=use_configfile,
        )
        if effective_user_selected_api_key:
            return PlanetAuthFactory._init_context_from_api_key(
                api_key=effective_user_selected_api_key,
            )

        #
        # Fall back to a built-in default configuration when all else fails.
        #
        if log_fallback_warning:
            auth_logger.warning(
                msg=f'Loading built-in profile "{Builtins.builtin_default_profile_name()}" as a fallback.'
            )

        return PlanetAuthFactory._init_context_from_profile(
            profile_name=Builtins.builtin_default_profile_name(),
            token_file_opt=token_file_opt,
            save_token_file=save_token_file,
        )

    @staticmethod
    def initialize_auth_client_context_from_custom_config(
        client_config: dict,
        profile_name: str,
        initial_token_data: Optional[dict] = None,
        save_token_file: bool = True,
        save_profile_config: bool = True,
        storage_provider: Optional[ObjectStorageProvider] = None,
    ) -> Auth:
        """
        Initialize using the provided client config dictionary
        and custom storage provider for session persistence.

        If a storage provider is not provided, a default file
        based storage provider will be used that is interoperable
        with the plauth CLI utility.  If a custom storage provider
        is supplied, sessions will not be visible to the plauth
        CLI tools.

        Parameters:
            client_config: The client configuration dictionary to use for authentication.
            profile_name: The name of the profile to use for the created auth context.
            initial_token_data: Optional initial token data to use for authentication.
                This may be used to pass in previously saved login state.
            save_token_file: Whether to save the access token to disk using the storage provider.
                If `False`, in-memory operation will be used, and login sessions will not be
                persisted.
            save_profile_config: Whether to save the profile configuration to disk using
                the storage provider.
            storage_provider: Optional custom storage provider for session persistence.
                If not provided, a default storage provider will be used that utilizes
                the user's home directory for storage.
        """
        return PlanetAuthFactory._init_context_from_client_config(
            client_config=client_config,
            profile_name=profile_name,
            initial_token_data=initial_token_data,
            save_token_file=save_token_file,
            save_profile_config=save_profile_config,
            storage_provider=storage_provider,
        )

    @staticmethod
    def initialize_resource_server_validator(
        environment: str,
        trusted_auth_server_configs: Optional[List[dict]] = None,
    ) -> OidcMultiIssuerValidator:
        """
        Create an OIDC multi issuer validator suitable for
        use by a resource server to validate access tokens in the
        specified deployment environment.

        If `"custom"` is selected, trusted_auth_server_configs` must also be specified.
        If custom is not selected, the aforementioned argument will be ignored.
        See `OidcMultiIssuerValidator.from_auth_server_configs` for more info.

        Parameters:
            environment: Specify a built-in environment to use for the validator.
                Valid environments are defined by built-in profile provider implemented
                by the application developer.
            trusted_auth_server_configs: A list of trusted auth server configurations
                to use if the environment is one designated as a custom environment
                by the built-in profile provider implemented by the application developer.
        """
        if not environment:
            raise ValueError(f"Passed environment must be one of {Builtins.builtin_environment_names()}.")

        environment = environment.upper()

        if environment not in Builtins.builtin_environment_names():
            raise ValueError(
                f"Passed environment must be one of {Builtins.builtin_environment_names()}. Instead, got: {environment}"
            )

        _builtin_trust_config = Builtins.builtin_environment(environment)

        if _builtin_trust_config is None:
            if trusted_auth_server_configs is None:
                raise MissingArgumentException(
                    "Custom or unknown environment was selected, but trusted_auth_server_configs was not supplied."
                )

            return OidcMultiIssuerValidator.from_auth_server_configs(trusted_auth_server_configs)

        if trusted_auth_server_configs is not None:
            warnings.warn(
                f"Custom environment not selected; trusted_auth_server_configs will be ignored in favor of the built in configuration for {environment}.",
                UserWarning,
            )

        return OidcMultiIssuerValidator.from_auth_server_configs(
            trusted_auth_server_configs=_builtin_trust_config,
        )


class MissingArgumentException(AuthException):
    """Raised when not all custom environment arguments are specified."""
