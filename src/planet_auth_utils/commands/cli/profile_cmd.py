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

import click
import sys
from collections import OrderedDict
from prompt_toolkit.shortcuts import input_dialog, radiolist_dialog

from planet_auth import AuthClient, AuthClientConfig, AuthException
from planet_auth.logging.auth_logger import getAuthLogger
from planet_auth.constants import (
    AUTH_CONFIG_FILE_PLAIN,
    AUTH_CONFIG_FILE_SOPS,
)

from planet_auth_utils.profile import Profile
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfig
from planet_auth_utils.constants import EnvironmentVariables
from .options import opt_long, opt_sops
from .util import recast_exceptions_to_click, print_obj

auth_logger = getAuthLogger()


def _handle_canceled():
    print("Canceled")
    sys.exit(1)


def _dialogue_choose_auth_client_type():
    choices = []
    for _, config_type in AuthClientConfig._get_typename_map().items():
        client_type = AuthClient._get_type_map().get(config_type)
        client_display_name = config_type.meta().get("display_name") or client_type.__name__
        client_description = config_type.meta().get("description")
        choices.append(([config_type, client_type], "{:40} - {}".format(client_display_name, client_description)))

    return (
        radiolist_dialog(
            title="Authentication Profile Creation",
            text="Select the auth client type.\n"
            "The auth client type determines how the software will interact with authentication and API"
            " services to make requests as the authenticated user.",
            values=choices,
        ).run()
        or _handle_canceled()
    )


def _dialogue_choose_auth_profile():
    filtered_builtin_profile_names = []
    for profile_name in Builtins.builtin_profile_names():
        config_dict = Builtins.builtin_profile_auth_client_config_dict(profile_name)
        # The idea of a "hidden" profile currently only applies to built-in profiles.
        # This is largely so we can have partial SKEL profiles.
        if not config_dict.get("_hidden", False):
            filtered_builtin_profile_names.append(profile_name)

    filtered_builtin_profile_names.sort()

    # Loading filters out invalid profile configurations that may be on disk
    sorted_on_disk_profile_names = list(_load_all_on_disk_profiles().keys())
    sorted_on_disk_profile_names.sort()
    all_profile_names = filtered_builtin_profile_names + sorted_on_disk_profile_names
    choices = []
    for profile_name in all_profile_names:
        choices.append((profile_name, f"{profile_name}"))
    return (
        radiolist_dialog(
            title="Authentication Builtins",
            text="Select the Authentication Profile to use",
            values=choices,
        ).run()
        or _handle_canceled()
    )


def _dialogue_enter_auth_profile_name():
    # TODO:
    #   - Check for collisions with existing profile or built in profiles.
    return (
        input_dialog(
            title="Auth Profile Creation",
            text="Select a name for the new client profile."
            "  Profile names should be legal file system names, and will be normalized.",
        ).run()
        or _handle_canceled()
    )


@click.group("profile", invoke_without_command=True)
@click.pass_context
def cmd_profile(ctx):
    """
    Manage auth profiles.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)


def _load_all_on_disk_profiles() -> dict:
    candidate_profile_names = Profile.list_on_disk_profiles()
    profiles_dicts = OrderedDict()
    for candidate_profile_name in candidate_profile_names:
        try:
            # conf = Profile.load_auth_client_config(candidate_profile_name)
            _, conf = PlanetAuthFactory.load_auth_client_config_from_profile(candidate_profile_name)
            profiles_dicts[candidate_profile_name] = conf
        except Exception as ex:
            auth_logger.debug(
                msg=f'"{candidate_profile_name}" was not a valid locally defined profile directory: {ex}'
            )

    return profiles_dicts


@cmd_profile.command("list")
@opt_long()
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_list(long):
    """
    List auth profiles.
    """
    click.echo("Built-in profiles:")
    profile_names = Builtins.builtin_profile_names().copy()
    profile_names.sort()
    display_dicts = OrderedDict()
    display_names = []
    for profile_name in profile_names:
        config_dict = Builtins.builtin_profile_auth_client_config_dict(profile_name)
        # The idea of a "hidden" profile currently only applies to built-in profiles.
        # This is largely so we can have partial SKEL profiles.
        if not config_dict.get("_hidden", False):
            display_dicts[profile_name] = config_dict
            display_names.append(profile_name)
    if long:
        print_obj(display_dicts)
    else:
        print_obj(display_names)

    click.echo("\nLocally defined profiles:")
    profile_dicts = _load_all_on_disk_profiles()
    profile_names = list(profile_dicts.keys())
    if long:
        print_obj(profile_dicts)
    else:
        print_obj(profile_names)


@cmd_profile.command("create")
@opt_sops()
@click.argument("new_profile_name", required=False)
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_create(sops, new_profile_name):
    """
    Wizard to create a new authentication profile.
    """
    # TODO: Non-interactive form?  The required args would be different for each type.
    #       If we conditionally prompt, what is the story? --no-sops? --quiet?  Pre-populate promts from CLI?
    # TODO: prompt for sops?
    # TODO: unify headless and interactive CL arg handling.
    # TODO: have a profile edit command that primes from an existing profile
    # TODO: Should the defaults not be meta but a more core feature
    # TODO: wrap text in narrow TTYs
    # TODO: rename config_hints meta to wizard hints?  This is NOT a config schema
    # TODO: can we take the config hint defaults from a populated dictionary? (meta['config_defaults'] ? )
    # TODO: We have no handling of non string types (Notably, handling "scopes" would be nice)

    if not new_profile_name:
        new_profile_name = _dialogue_enter_auth_profile_name()

    config_type, client_type = _dialogue_choose_auth_client_type()  # pylint: disable=W0612

    if sops:
        dst_config_filepath = Profile.get_profile_file_path(profile=new_profile_name, filename=AUTH_CONFIG_FILE_SOPS)
    else:
        dst_config_filepath = Profile.get_profile_file_path(profile=new_profile_name, filename=AUTH_CONFIG_FILE_PLAIN)

    config_dict = {
        AuthClientConfig.CLIENT_TYPE_KEY: config_type.meta().get("client_type"),
    }

    if config_type.meta().get("config_hints"):
        for hint in config_type.meta().get("config_hints"):
            config_value = input_dialog(
                title="{} Configuration: {}".format(config_type.meta().get("display_name"), hint.get("config_key")),
                text="{} ({})\n{}".format(
                    hint.get("config_key_name"), hint.get("config_key"), hint.get("config_key_description")
                ),
                default=hint.get("config_key_default") or "",
                cancel_text="Skip",  # since we keep going...
            ).run()  # or _handle_canceled() Users can skip config values.
            config_dict[hint.get("config_key")] = config_value

    new_auth_client_config = config_type(file_path=dst_config_filepath, **config_dict)
    new_auth_client_config.save()


@cmd_profile.command("edit")
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_edit():
    """
    Edit an existing profile.
    """
    raise AuthException("Function not implemented")


# Separte help since the docstring here is developer oriented, not user oriented.
@cmd_profile.command(
    "copy",
    help="Copy an existing profile to create a new profile.  Only the persistent"
    " profile configuration will be copied.  User access tokens initialized"
    " via a call to `login` will not be copied.",
)
@click.argument("src")
@click.argument("dst")
@opt_sops()
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_copy(sops, src, dst):
    """
    Copy an existing profile to create a new profile.  Only the persistent
    profile configuration will be copied.  User access tokens initialized
    via a call to `login` will not be copied.

    Note: Depending on the type of [planet_auth.AuthClient] configured in
    the source profile, the new profile may have long term credentials
    (e.g. OAuth client credential secrets, API keys. etc.).

    Note: External support files, such as public/private keypair files,
    are not copied.

    This command will work with built-in as well as custom profiles,
    so it is possible to bootstrap profiles to manage multiple user
    identities with an otherwise default client profile:
    ```
    profile copy my_app_builtin_default <my_new_profile>
    ```

    """
    # TODO: consider fixing the copying of support files like key pairs when
    #       pubkeys are used.  To do that properly, their paths should be
    #       relative to the profile dir, and not absolute, but that is not
    #       currently implemented.
    _, auth_config = PlanetAuthFactory.load_auth_client_config_from_profile(src)
    if sops:
        dst_config_filepath = Profile.get_profile_file_path(profile=dst, filename=AUTH_CONFIG_FILE_SOPS)
    else:
        dst_config_filepath = Profile.get_profile_file_path(profile=dst, filename=AUTH_CONFIG_FILE_PLAIN)

    auth_config.set_path(dst_config_filepath)
    # No need to specify provider. The CLI is only concerned with the
    # default file based storage provider for now.
    # auth_config.auth_client().config().set_storage_provider()
    auth_config.save()


@cmd_profile.command("set")
@click.argument("selected_profile", required=False)
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_set(selected_profile):
    """
    Configure the default authentication profile. Preference will be saved to disk
    and will be used when one is not otherwise specified.  Command line options
    and environment variables override on-disk preferences.
    """
    if not selected_profile:
        selected_profile = _dialogue_choose_auth_profile()
    else:
        # Validate user input.  Dialogue selected profiles should be pre-vetted.
        normalized_profile_name, _ = PlanetAuthFactory.load_auth_client_config_from_profile(selected_profile)
        selected_profile = normalized_profile_name

    try:
        user_profile_config_file = PlanetAuthUserConfig()
        user_profile_config_file.load()
    except FileNotFoundError:
        user_profile_config_file = PlanetAuthUserConfig(data={})

    user_profile_config_file.update_data({EnvironmentVariables.AUTH_PROFILE: selected_profile})
    user_profile_config_file.save()


@cmd_profile.command("show")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_show(ctx):
    """
    Show the current authentication profiles.
    """
    print(f'Current: {ctx.obj["AUTH"].profile_name()}')
    try:
        user_profile_config_file = PlanetAuthUserConfig()
        print(f"User Default: {user_profile_config_file.lazy_get(EnvironmentVariables.AUTH_PROFILE)}")
    except Exception:  #  as ex:
        # print(f'User Default: {ex}')
        print("User Default: N/A")

    print(f"Global Built-in Default: {Builtins.builtin_default_profile_name()}")
