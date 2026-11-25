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

import os
import re
import warnings

from typing import Dict, List, Optional, Set, Tuple

from planet_auth import (
    Auth,
    AuthClientConfig,
    AuthClientConfigIncompleteException,
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

from planet_auth_utils.profile import Profile, ProfileException
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
    def derived_profile_name(base_profile_name: str, client_id: str) -> str:
        """
        Construct the name used for a profile derived from a base profile
        and a client ID.  The result is safe for use as a directory name.
        """
        safe_client_id = re.sub(r"[^a-z0-9._-]+", "_", client_id.lower()).strip("._") or "client"
        return f"{base_profile_name.lower()}-{safe_client_id}"

    @staticmethod
    def _missing_config_keys(auth_client_config: AuthClientConfig) -> Set[str]:
        missing_keys: Set[str] = set()
        for m in auth_client_config.missing_required_fields():
            missing_keys.update(m["config_key"].split("|"))
        return missing_keys

    @staticmethod
    def _profile_accepts_overrides(auth_client_config: AuthClientConfig, overrides: Dict[str, "_ResolvedSetting"]):
        """
        True if every override either fills in a required setting the profile
        lacks, or matches what the profile already has.
        """
        missing_keys = PlanetAuthFactory._missing_config_keys(auth_client_config)
        data = auth_client_config.data() or {}
        return all(k in missing_keys or data.get(k) == s.value for k, s in overrides.items())

    @staticmethod
    def _warn_on_derived_profile_mismatch(profile_name: str, merged_config: dict):
        """
        A derived profile may share a name with one already saved on disk,
        for example by a previous `login`.  The runtime configuration takes
        priority over the saved one, as it always has.  Warn if they refer to
        different clients or auth servers, since tokens saved under the
        profile may not be valid for the runtime configuration.
        """
        try:
            existing = Profile.load_auth_client_config(profile_name)
            existing.lazy_load()
        except FileNotFoundError:
            return
        except AuthException as e:
            auth_logger.debug(msg=f'Ignoring unreadable saved profile "{profile_name}": {e}')
            return
        existing_data = existing.data() or {}
        for key in ("client_type", "auth_server", "client_id"):
            if existing_data.get(key) != merged_config.get(key):
                auth_logger.warning(
                    msg=f'Saved profile "{profile_name}" ("{existing.path()}") has a different {key}'
                    f' ("{existing_data.get(key)}") than the runtime configuration ("{merged_config.get(key)}").'
                    " The saved profile configuration is ignored."
                )
                return

    @staticmethod
    def _incomplete_profile_exception(
        profile_name: str, e: AuthClientConfigIncompleteException
    ) -> AuthClientConfigIncompleteException:
        missing_fields = e.missing_fields()
        message = (
            f'Auth profile "{profile_name}" is incomplete. Missing required settings: '
            + ", ".join(f'{m["config_key_name"]} ({m["config_key"]})' for m in missing_fields)
            + "."
        )
        # Env var names depend on the built-in provider namespace, so build these lazily.
        runtime_override_hints = {
            "client_id": f"the client ID (--auth-client-id or {EnvironmentVariables.AUTH_CLIENT_ID})",
            "client_secret": f"the client secret (--auth-client-secret or {EnvironmentVariables.AUTH_CLIENT_SECRET})",
        }
        hints = [
            runtime_override_hints[m["config_key"]]
            for m in missing_fields
            if m["config_key"] in runtime_override_hints
        ]
        if hints and len(hints) == len(missing_fields):
            message += " Supply " + " and ".join(hints) + ", or save"
        else:
            message += " Save"
        message += f" a complete profile with `profile copy {profile_name} <new profile name>`."
        return AuthClientConfigIncompleteException(
            missing_fields=missing_fields, profile_name=profile_name, message=message
        )

    @staticmethod
    def _init_context_from_profile_with_overrides(
        base_profile_name: str,
        base_config: AuthClientConfig,
        overrides: Dict[str, "_ResolvedSetting"],
        token_file_opt: Optional[str] = None,
        save_token_file: bool = True,
        save_profile_config: bool = False,
    ) -> Auth:
        """
        Initialize from a base profile, combined with override settings.
        Overrides only fill required settings that the base profile is
        missing; they never replace values it already has.  Ignored overrides
        are logged with their source.

        When an override supplies the client ID, the runtime profile is given a
        derived name (see `derived_profile_name()`), so that template profiles
        such as built-in M2M profiles are never shadowed.  When nothing is
        merged, the base profile is used as is.
        """
        base_config.lazy_load()
        base_data = dict(base_config.data() or {})
        missing_keys = PlanetAuthFactory._missing_config_keys(base_config)

        merged_data = dict(base_data)
        applied: Dict[str, _ResolvedSetting] = {}
        for key, setting in overrides.items():
            if key in missing_keys:
                merged_data[key] = setting.value
                applied[key] = setting
            elif base_data.get(key) != setting.value:
                reason = f"already sets {key}" if base_data.get(key) else f"does not use {key}"
                auth_logger.info(msg=f'{setting.describe()} ignored. Profile "{base_profile_name}" {reason}.')

        if applied:
            merged_data.pop("_hidden", None)
            runtime_config = AuthClientConfig.from_dict(merged_data)
        else:
            runtime_config = base_config

        try:
            runtime_config.check_complete()
        except AuthClientConfigIncompleteException as e:
            raise PlanetAuthFactory._incomplete_profile_exception(base_profile_name, e) from e

        runtime_profile_name = base_profile_name
        if applied:
            if "client_id" in applied:
                runtime_profile_name = PlanetAuthFactory.derived_profile_name(
                    base_profile_name, merged_data["client_id"]
                )
            if Builtins.is_builtin_profile(runtime_profile_name):
                raise ProfileConflictException(
                    message=f'Profile "{base_profile_name}" cannot be combined with '
                    + ", ".join(s.describe() for s in applied.values())
                    + f' without shadowing built-in profile "{runtime_profile_name}".'
                    f" Create a custom profile with `profile copy {base_profile_name} <new name>` instead."
                )
            PlanetAuthFactory._warn_on_derived_profile_mismatch(runtime_profile_name, merged_data)
            auth_logger.debug(
                msg=f'Combined profile "{base_profile_name}" with '
                + ", ".join(s.describe() for s in applied.values())
                + f' as runtime profile "{runtime_profile_name}"'
            )

        token_file_path = PlanetAuthFactory._token_file_path(
            profile_name=runtime_profile_name, overide_path=token_file_opt, save_token_file=save_token_file
        )
        auth_logger.debug(msg=f"Initializing Auth from profile {runtime_profile_name}")
        plauth_context = Auth.initialize_from_config(
            client_config=runtime_config,
            token_file=token_file_path,
            profile_name=runtime_profile_name,
        )
        if save_profile_config and applied:
            PlanetAuthFactory._update_saved_profile_config(plauth_context=plauth_context)

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

        Each of the profile, OAuth client ID, OAuth client secret, and API key
        settings is resolved independently using the priority above.  The
        resolved settings are then combined to construct the returned Auth context:

        - If a profile was selected and it can accept the resolved client
          credentials, they are combined.  A profile can accept credentials
          when they fill in required settings it lacks (for example, a built-in
          M2M profile that serves as a template and has no client ID or secret),
          or when they match the values it already has.  Credentials never
          replace values a profile already has; ignored settings are logged.
          When the client ID is supplied this way, the runtime profile is named
          `<profile>-<client id>`.  Such derived names will never shadow a
          built-in profile.  If a saved profile of the same name exists, the
          runtime configuration takes priority, and a warning is logged if the
          saved profile refers to a different client or auth server.
        - Otherwise, the profile, a complete set of client credentials, or the
          API key is used, whichever came from the highest priority source.  Ties
          go to the profile, then to client credentials, then to the API key.
          Client credentials used without a profile are combined with the
          default built-in M2M profile.
        - A user selected profile that is incomplete is an error if it was
          explicitly selected.  If it was selected by environment or config
          file, a warning is logged and other options are considered.
        - If no other selection has been made, a built-in default auth profile
          is used, which may require interactive user authentication.

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
        # Each setting is resolved independently, with the priority
        # explicit argument > environment > config file.  Settings are then
        # combined: credentials are merged into the selected profile when the
        # profile can accept them (i.e., they fill in what a template profile
        # is missing).  When they cannot be combined, the setting from the
        # higher priority source wins.
        #
        user_config_file = PlanetAuthUserConfigEnhanced()

        def _resolve(label: str, env_var: str, override_value: Optional[str], secret: bool = False):
            return _ResolvedSetting.resolve(
                label=label,
                env_var=env_var,
                override_value=override_value,
                user_config_file=user_config_file,
                use_env=use_env,
                use_configfile=use_configfile,
                secret=secret,
            )

        profile_setting = _resolve("profile", EnvironmentVariables.AUTH_PROFILE, auth_profile_opt)
        _cred_settings = {
            "client_id": _resolve("client ID", EnvironmentVariables.AUTH_CLIENT_ID, auth_client_id_opt),
            "client_secret": _resolve(
                "client secret", EnvironmentVariables.AUTH_CLIENT_SECRET, auth_client_secret_opt, secret=True
            ),
        }
        cred_overrides: Dict[str, _ResolvedSetting] = {k: v for k, v in _cred_settings.items() if v}
        api_key_setting = _resolve("API key", EnvironmentVariables.AUTH_API_KEY, auth_api_key_opt, secret=True)
        if not api_key_setting:
            # For backwards compatibility, we know the old SDK used this in json files.
            api_key_setting = _ResolvedSetting.resolve(
                label="API key",
                env_var="key",
                override_value=None,
                user_config_file=user_config_file,
                use_env=False,
                use_configfile=use_configfile,
                secret=True,
            )

        #
        # Load the selected profile, if any.  An explicitly selected profile
        # that cannot be loaded is an error.  A profile selected implicitly
        # (env or config file) that cannot be loaded produces a warning, and
        # we fall through to other options.
        #
        log_fallback_warning = False
        profile_name = None
        profile_config: Optional[AuthClientConfig] = None
        if profile_setting:
            try:
                profile_name, profile_config = PlanetAuthFactory.load_auth_client_config_from_profile(
                    profile_setting.value
                )
                profile_config.lazy_load()
            except Exception as e:
                if profile_setting.rank == _ResolvedSetting.RANK_EXPLICIT:
                    raise
                auth_logger.warning(
                    msg=f'Unable to load user selected profile "{profile_setting.value}" ({profile_setting.source}).'
                    f" Error: {e}"
                )
                profile_config = None
                log_fallback_warning = True

        have_full_creds = "client_id" in cred_overrides and "client_secret" in cred_overrides
        cred_rank = min(s.rank for s in cred_overrides.values()) if have_full_creds else None

        # Choose by source priority (lower rank wins).  A profile that can
        # absorb the credentials is combined with them, so it is never in
        # conflict with them.  Ties preserve the historical order:
        # profile, then OAuth client credentials, then API key.
        candidates = []
        if profile_config is not None and profile_setting:
            profile_rank = profile_setting.rank
            if cred_overrides and PlanetAuthFactory._profile_accepts_overrides(profile_config, cred_overrides):
                profile_rank = min([profile_rank] + [s.rank for s in cred_overrides.values()])
            candidates.append((profile_rank, 0, "profile"))
        if have_full_creds:
            candidates.append((cred_rank, 1, "creds"))
        if api_key_setting:
            candidates.append((api_key_setting.rank, 2, "api_key"))
        selected = min(candidates)[2] if candidates else None

        if selected == "profile":
            try:
                return PlanetAuthFactory._init_context_from_profile_with_overrides(
                    base_profile_name=profile_name,  # type: ignore
                    base_config=profile_config,  # type: ignore
                    overrides=cred_overrides,
                    token_file_opt=token_file_opt,
                    save_token_file=save_token_file,
                    save_profile_config=save_profile_config,
                )
            except AuthClientConfigIncompleteException as e:
                if profile_setting.rank == _ResolvedSetting.RANK_EXPLICIT:  # type: ignore
                    raise
                auth_logger.warning(msg=f"{e} The profile was selected by {profile_setting.source}.")  # type: ignore
                log_fallback_warning = True
                selected = "creds" if have_full_creds else ("api_key" if api_key_setting else None)

        if selected == "creds":
            if profile_config is not None and profile_setting:
                auth_logger.info(
                    msg=f'Profile "{profile_name}" ({profile_setting.source}) ignored in favor of'
                    f" {cred_overrides['client_id'].describe()}."
                )
            # TODO: support oauth service accounts that use pubkey, and not just client secrets.
            m2m_realm_name = Builtins.builtin_default_profile_name(client_type="oidc_client_credentials_secret")
            return PlanetAuthFactory._init_context_from_profile_with_overrides(
                base_profile_name=m2m_realm_name,
                base_config=Builtins.load_builtin_auth_client_config(m2m_realm_name),
                overrides=cred_overrides,
                token_file_opt=token_file_opt,
                save_token_file=save_token_file,
                save_profile_config=save_profile_config,
            )

        if selected == "api_key":
            return PlanetAuthFactory._init_context_from_api_key(
                api_key=api_key_setting.value,  # type: ignore
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


class ProfileConflictException(ProfileException):
    """
    Raised when combining a profile with other settings would shadow a
    built-in profile.
    """


class _ResolvedSetting:
    """
    A configuration value, and a record of where it came from.
    Lower ranks are higher priority.
    """

    RANK_EXPLICIT = 0
    RANK_ENV = 1
    RANK_CONFIG_FILE = 2

    def __init__(self, label: str, value: str, rank: int, source: str, secret: bool = False):
        self.label = label
        self.value = value
        self.rank = rank
        self.source = source
        self.secret = secret

    def describe(self) -> str:
        if self.secret:
            return f"{self.label} from {self.source}"
        return f'{self.label} "{self.value}" from {self.source}'

    @staticmethod
    def resolve(
        label: str,
        env_var: str,
        override_value: Optional[str],
        user_config_file: PlanetAuthUserConfigEnhanced,
        use_env: bool,
        use_configfile: bool,
        secret: bool = False,
    ) -> Optional["_ResolvedSetting"]:
        if override_value:
            return _ResolvedSetting(label, override_value, _ResolvedSetting.RANK_EXPLICIT, "explicit option", secret)
        if use_env and os.getenv(env_var):
            return _ResolvedSetting(
                label, os.getenv(env_var), _ResolvedSetting.RANK_ENV, f"environment variable {env_var}", secret  # type: ignore
            )
        if use_configfile:
            value = user_config_file.effective_conf_value(config_key=env_var, use_env=False, use_configfile=True)
            if value:
                return _ResolvedSetting(
                    label,
                    value,
                    _ResolvedSetting.RANK_CONFIG_FILE,
                    f'"{env_var}" in config file "{user_config_file.path()}"',
                    secret,
                )
        return None
