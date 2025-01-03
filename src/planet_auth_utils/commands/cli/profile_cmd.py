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

import click
import logging
import sys
from collections import OrderedDict
from prompt_toolkit.shortcuts import input_dialog, radiolist_dialog

from planet_auth import AuthClient, AuthClientConfig, AuthException
from planet_auth.constants import (
    AUTH_CONFIG_FILE_PLAIN,
    AUTH_CONFIG_FILE_SOPS,
)

from planet_auth_utils.profile import Profile
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfig
from planet_auth_utils.constants import EnvironmentVariables
from .options import opt_long, opt_sops
from .util import recast_exceptions_to_click, print_obj

logger = logging.getLogger(__name__)


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
    all_profile_names = Builtins.builtin_profile_names() + Profile.list_on_disk_profiles()
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
def profile_cmd_group(ctx):
    """
    Manage auth profiles.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)


def _load_all_on_disk_profiles() -> dict:
    # Any directory in ~/.planet is only a potential profile. We only
    # consider it an actual profile if a valid client config file can be found.
    candidate_profile_names = [x.name for x in Profile.profile_root().iterdir() if x.is_dir()]
    candidate_profile_names.sort()
    profiles_dicts = OrderedDict()
    for candidate_profile_name in candidate_profile_names:
        try:
            conf = Profile.load_client_config(candidate_profile_name)
            profiles_dicts[candidate_profile_name] = conf
        except Exception as ex:
            logger.debug(msg=f'"{candidate_profile_name}" was not a valid local profile directory: {ex}')

    return profiles_dicts


@profile_cmd_group.command("list")
@opt_long
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_list(long):
    """
    List auth profiles.
    """
    if long:
        click.echo("Built-in profiles:")
        profile_names = Builtins.builtin_profile_names().copy()
        profile_names.sort()
        display_object = OrderedDict()
        for profile_name in profile_names:
            config_dict = Builtins.builtin_profile_auth_client_config_dict(profile_name)
            display_object[profile_name] = config_dict
        print_obj(display_object)

        click.echo("\nLocally defined profiles:")
        print_obj(_load_all_on_disk_profiles())

    else:
        click.echo("Built-in profiles:")
        profile_names = Builtins.builtin_profile_names().copy()
        profile_names.sort()
        print_obj(profile_names)
        click.echo("\nLocally defined profiles:")
        profile_names = Profile.list_on_disk_profiles()
        profile_names.sort()
        print_obj(profile_names)


@profile_cmd_group.command("create")
@opt_sops
@click.argument("new_profile_name", required=False)
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_create(sops, new_profile_name):
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


@profile_cmd_group.command("edit")
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_edit():
    """
    Edit an existing profile.
    """
    raise AuthException("Function not implemented")


@profile_cmd_group.command("copy")
@click.argument("src")
@click.argument("dst")
@opt_sops
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_copy(sops, src, dst):
    """
    Copy an existing profile to create a new profile.  Only the persistent
    profile configuration will be copied.  User access tokens initialized
    via a call to `login` will not be copied.  Note: Depending on the
    type of [planet_auth.AuthClient] configured in the source profile,
    the new profile may have long term credentials (e.g. OAuth
    client credential secrets, API keys. etc.).  External support files,
    such as public/private keypair files, are not copied.

    This command will work with built-in as well as custom profiles,
    so it is possible to bootstrap profiles to manage multiple user
    identities with an otherwise default client profile:
    ```
    profile copy default <my_new_profile>
    profile copy legacy  <my_new_profile>
    ```

    """
    # TODO: consider fixing the copying of support files like key pairs when
    #       pubkeys are used.  To do that properly, their paths should be
    #       relative to the profile dir, and not absolute, but that is not
    #       currently implemented.
    auth_config = Builtins.load_auth_client_config(src)
    if sops:
        dst_config_filepath = Profile.get_profile_file_path(profile=dst, filename=AUTH_CONFIG_FILE_SOPS)
    else:
        dst_config_filepath = Profile.get_profile_file_path(profile=dst, filename=AUTH_CONFIG_FILE_PLAIN)

    auth_config.set_path(dst_config_filepath)
    auth_config.save()


@profile_cmd_group.command("set")
@click.argument("selected_profile", required=False)
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_set(selected_profile):
    """
    Configure the default authentication profile to use when one is not otherwise specified.
    """
    if not selected_profile:
        selected_profile = _dialogue_choose_auth_profile()

    try:
        user_profile_config_file = PlanetAuthUserConfig()
        user_profile_config_file.load()
    except FileNotFoundError:
        user_profile_config_file = PlanetAuthUserConfig(data={})

    user_profile_config_file.update_data({EnvironmentVariables.AUTH_PROFILE: selected_profile})
    user_profile_config_file.save()


@profile_cmd_group.command("show")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_show(ctx):
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
    print(f"Global Built-in Default: {Builtins.dealias_builtin_profile(Builtins.builtin_default_profile_name())}")
