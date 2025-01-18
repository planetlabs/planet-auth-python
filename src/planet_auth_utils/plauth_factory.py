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

import logging
import warnings

from typing import List, Optional

from planet_auth import (
    Auth,
    OidcMultiIssuerValidator,
    PlanetLegacyRequestAuthenticator,
    AuthException,
)
from planet_auth.constants import TOKEN_FILE_SOPS, TOKEN_FILE_PLAIN

from planet_auth_utils.profile import Profile
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfigEnhanced
from planet_auth_utils.constants import EnvironmentVariables

logger = logging.getLogger(__name__)


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
    def _init_context_from_profile(
        profile_name: str,
        token_file_opt: Optional[str] = None,
        save_token_file: bool = True,
        log_fallback_warning: bool = False,
    ) -> Auth:
        normalized_builtin_profile = Builtins.dealias_builtin_profile(profile_name)
        if normalized_builtin_profile:
            user_selected_profile = normalized_builtin_profile
        else:
            user_selected_profile = profile_name.lower()

        token_file_path = PlanetAuthFactory._token_file_path(
            profile_name=user_selected_profile, overide_path=token_file_opt, save_token_file=save_token_file  # type: ignore
        )
        auth_client_config = Builtins.load_auth_client_config(user_selected_profile)
        if log_fallback_warning:
            logger.warning('Client profile "%s" selected as a fallback.', user_selected_profile)
        return Auth.initialize_from_config(
            client_config=auth_client_config,
            token_file=token_file_path,
            profile_name=user_selected_profile,
        )

    @staticmethod
    def _init_context_from_oauth_svc_account(
        client_id: str,
        client_secret: str,
        token_file_opt: Optional[str] = None,
        save_token_file: bool = True,
    ) -> Auth:
        # TODO: support oauth service accounts that use pubkey, and not just client secrets.
        # TODO: Can we handle different trust realms when initializing a M2M client with
        #       just the Client ID and secret? (akin to how AUTH0_DOMAIN works)
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

        return Auth.initialize_from_config_dict(
            client_config=constructed_client_config_dict,
            token_file=token_file_path,
            profile_name=adhoc_profile_name,
        )

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
        adhoc_profile_name = "_PL_API_KEY"
        return Auth.initialize_from_config_dict(
            client_config=constructed_client_config_dict,
            token_file=None,
            profile_name=adhoc_profile_name,
        )

    @staticmethod
    def initialize_auth_client_context(
        auth_profile_opt: Optional[str] = None,
        auth_client_id_opt: Optional[str] = None,
        auth_client_secret_opt: Optional[str] = None,
        auth_api_key_opt: Optional[str] = None,  # Deprecated
        token_file_opt: Optional[str] = None,  # TODO: Remove, but we still depend on it for Planet Legacy use cases.
        save_token_file: bool = True,
    ) -> Auth:
        """
        Helper function to initialize the Auth context in applications.

        Between built-in profiles to interactively login users, customer or third party
        registered OAuth clients and corresponding custom profiles that may be saved on disk,
        OAuth service account profiles, and static API keys, there are a number of
        ways to configure how an application build with this library should authenticate
        requests made to the service.  Add to this, configration may come from explict
        parameters set by the user, environment variables, or configuration files, and the
        number of possibilities rises.

        This helper function is provided to help build applications with a consistent
        user experience.

        Arguments to this function are taken to be explicitly set by the user, and are
        given the highest priority.  Internally, the priority used for the source of
        any particular configuration values is, from highest to lowest priority, as follows:
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
            @opt_auth_profile
            @opt_auth_client_id
            @opt_auth_client_secret
            @click.pass_context
            def my_cli_main(ctx, auth_profile, auth_client_id, auth_client_secret):
                ctx.ensure_object(dict)
                ctx.obj["AUTH"] = PlanetAuthFactory.initialize_auth_client_context(
                    auth_profile_opt=auth_profile, auth_client_id_opt=auth_client_id, auth_client_secret_opt=auth_client_secret
                )
                # Click program may now use the auth context in all commands...
            ```
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
        )
        if effective_user_selected_profile:
            try:
                return PlanetAuthFactory._init_context_from_profile(
                    profile_name=effective_user_selected_profile,
                    token_file_opt=token_file_opt,
                    save_token_file=save_token_file,
                )
            except Exception as e:
                logger.warning(
                    'Unable to initialize user selected profile "%s".'
                    ' Profile was selected from %s environment variable or "%s" configuration file.'
                    " Error: %s",
                    effective_user_selected_profile,
                    EnvironmentVariables.AUTH_PROFILE,
                    user_config_file.path(),
                    e,
                )
                log_fallback_warning = True

        effective_user_selected_client_id = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_CLIENT_ID,
            override_value=auth_client_id_opt,
        )
        effective_user_selected_client_secret = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_CLIENT_SECRET,
            override_value=auth_client_secret_opt,
        )
        if effective_user_selected_client_id and effective_user_selected_client_secret:
            return PlanetAuthFactory._init_context_from_oauth_svc_account(
                client_id=effective_user_selected_client_id,
                client_secret=effective_user_selected_client_secret,
                token_file_opt=token_file_opt,
                save_token_file=save_token_file,
            )

        effective_user_selected_api_key = user_config_file.effective_conf_value(
            config_key=EnvironmentVariables.AUTH_API_KEY,
            override_value=auth_api_key_opt,
        )
        if effective_user_selected_api_key:
            return PlanetAuthFactory._init_context_from_api_key(
                api_key=effective_user_selected_api_key,
            )

        effective_user_selected_api_key = user_config_file.effective_conf_value(
            config_key="key",  # For backwards compatibility
            override_value=auth_api_key_opt,
            use_env=False,
        )
        if effective_user_selected_api_key:
            return PlanetAuthFactory._init_context_from_api_key(
                api_key=effective_user_selected_api_key,
            )
        #
        # Fall back to a built-in default configuration when all else fails.
        #
        return PlanetAuthFactory._init_context_from_profile(
            profile_name=Builtins.builtin_default_profile_name(),
            token_file_opt=token_file_opt,
            save_token_file=save_token_file,
            log_fallback_warning=log_fallback_warning,
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

        The passed `environment` must be one of `"production"`, `"staging"`,
        or `"custom"`. `environment` is case-insensitive.

        If `"custom"` is selected, trusted_auth_server_configs` must also be specified.
        If custom is not selected, the aforementioned argument will be ignored.
        See `OidcMultiIssuerValidator.from_auth_server_configs` for more info.
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
