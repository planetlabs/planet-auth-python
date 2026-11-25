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
import json
import sys
from collections import OrderedDict
from typing import List, Optional, Tuple
from prompt_toolkit.shortcuts import input_dialog, radiolist_dialog

from planet_auth import (
    AuthClient,
    AuthClientConfig,
    AuthClientConfigIncompleteException,
    AuthException,
    ObjectStorageProvider,
    OidcAuthClient,
)
from planet_auth.logging.auth_logger import getAuthLogger
from planet_auth.constants import (
    AUTH_CONFIG_FILE_PLAIN,
    AUTH_CONFIG_FILE_SOPS,
)

from planet_auth_utils.profile import Profile
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfig, PlanetAuthUserConfigEnhanced
from planet_auth_utils.constants import EnvironmentVariables
from .options import opt_client_id, opt_client_secret, opt_long, opt_sops
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

    incomplete_notes = []
    for profile_name in display_names:
        conf = AuthClientConfig.from_dict(display_dicts[profile_name])
        missing = conf.missing_required_fields()
        if missing:
            incomplete_notes.append(
                f'  "{profile_name}" (built-in template) is missing {_missing_keys_text(missing)}.'
                f" Use `profile copy {profile_name} <new profile name>` to create a profile from it."
            )
    for profile_name, conf in profile_dicts.items():
        missing = conf.missing_required_fields()
        if missing:
            incomplete_notes.append(
                f'  "{profile_name}" is missing {_missing_keys_text(missing)}.'
                f" Run `profile check {profile_name}` for details."
            )
    if incomplete_notes:
        click.echo("\nIncomplete profiles:\n" + "\n".join(incomplete_notes), err=True)


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


def _missing_keys_text(missing_fields: List[dict]) -> str:
    return ", ".join(m["config_key"] for m in missing_fields)


def _missing_fields_detail_text(missing_fields: List[dict]) -> str:
    lines = []
    for m in missing_fields:
        line = f'  - {m["config_key_name"]} ({m["config_key"]})'
        if m.get("config_key_description"):
            line += f': {m["config_key_description"]}'
        lines.append(line)
    return "\n".join(lines)


def _parse_set_values(set_values) -> dict:
    result = {}
    for set_value in set_values or []:
        key, sep, value = set_value.partition("=")
        key = key.strip()
        if not sep or not key:
            raise click.BadParameter(f'"{set_value}" is not in the form KEY=VALUE.', param_hint="--set")
        if value.startswith(("[", "{")):
            # Allow structured values such as lists of scopes or audiences.
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise click.BadParameter(f'Invalid JSON value for "{key}": {e}', param_hint="--set")
        result[key] = value
    return result


def _copy_options_for_missing_fields(missing_fields: List[dict]) -> str:
    requirements = []
    for m in missing_fields:
        alternatives = [_COPY_OPTIONS_BY_CONFIG_KEY.get(k, f"--set {k}=<value>") for k in m["config_key"].split("|")]
        requirements.append(" or ".join(alternatives))
    return " and ".join(requirements)


_COPY_OPTIONS_BY_CONFIG_KEY = {
    "client_id": "--auth-client-id <client id>",
    "client_secret": "--auth-client-secret <client secret>",
}


def _is_secret_config_key(config_key: str) -> bool:
    return any(s in config_key for s in ("secret", "password", "privkey", "api_key"))


def _prompt_for_missing_fields(auth_config: AuthClientConfig) -> AuthClientConfig:
    data = dict(auth_config.data() or {})
    hints = {h["config_key"]: h for h in (auth_config.meta().get("config_hints") or [])}
    for missing in auth_config.missing_required_fields():
        alternatives = missing["config_key"].split("|")
        if len(alternatives) > 1:
            click.echo(f'{missing["config_key_name"]} is required. Enter one of them.')
        for config_key in alternatives:
            hint = hints.get(config_key, {})
            value = click.prompt(
                f'{hint.get("config_key_name", config_key)} ({config_key}) [leave blank to skip]',
                default=hint.get("config_key_default") or "",
                show_default=bool(hint.get("config_key_default")),
                hide_input=_is_secret_config_key(config_key),
            )
            if value:
                data[config_key] = value
                break
    return AuthClientConfig.from_dict(data)


def _existing_profile_config_paths(profile_name: str):
    # Profile paths are storage keys, not paths relative to the CWD.
    storage_provider = ObjectStorageProvider._default_storage_provider()
    return [
        p
        for p in (
            Profile.get_profile_file_path(profile=profile_name, filename=AUTH_CONFIG_FILE_SOPS),
            Profile.get_profile_file_path(profile=profile_name, filename=AUTH_CONFIG_FILE_PLAIN),
        )
        if storage_provider.obj_exists(p)
    ]


# Separte help since the docstring here is developer oriented, not user oriented.
@cmd_profile.command(
    "copy",
    help="Copy an existing profile to create a new profile.  Only the persistent"
    " profile configuration will be copied.  User access tokens initialized"
    " via a call to `login` will not be copied."
    "\n\nThe source may be an incomplete template profile, such as a built-in"
    " M2M profile that lacks a client ID and secret.  Missing settings may be"
    " supplied with options, or entered interactively.  Incomplete profiles may"
    " still be saved, and completed later.",
)
@click.argument("src")
@click.argument("dst")
@opt_client_id(envvar=None)
@opt_client_secret(envvar=None)
@click.option(
    "--set",
    "set_values",
    multiple=True,
    metavar="KEY=VALUE",
    help="Set a configuration value in the new profile.  May be repeated."
    "  Values beginning with '[' or '{' are parsed as JSON.",
)
@click.option(
    "--prompt/--no-prompt",
    default=None,
    help="Prompt for required settings that are missing from the new profile."
    "  By default, prompt only when attached to a terminal.",
)
@click.option("--force", is_flag=True, default=False, help="Overwrite the destination profile if it exists.")
@opt_sops()
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_copy(src, dst, auth_client_id, auth_client_secret, set_values, prompt, force, sops):
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

    Incomplete profiles, such as built-in M2M profiles that serve as templates,
    may be used as the source, with missing values supplied by options or prompts:
    ```
    profile copy my_app_builtin_m2m <my_new_profile> --auth-client-id <id> --auth-client-secret <secret>
    ```
    """
    # TODO: consider fixing the copying of support files like key pairs when
    #       pubkeys are used.  To do that properly, their paths should be
    #       relative to the profile dir, and not absolute, but that is not
    #       currently implemented.
    dst = dst.lower()
    if Builtins.is_builtin_profile(dst):
        raise click.ClickException(f'"{dst}" is the name of a built-in profile. Choose another name.')

    if sops:
        dst_config_filepath = Profile.get_profile_file_path(profile=dst, filename=AUTH_CONFIG_FILE_SOPS)
    else:
        dst_config_filepath = Profile.get_profile_file_path(profile=dst, filename=AUTH_CONFIG_FILE_PLAIN)

    existing_paths = _existing_profile_config_paths(dst)
    if existing_paths and not force:
        raise click.ClickException(
            f'Profile "{dst}" already exists ("{existing_paths[0]}"). Use --force to overwrite it.'
        )
    if any(p != dst_config_filepath for p in existing_paths):
        # The SOPS file would take priority over a plain file when loading, and we
        # will not delete one on behalf of the user.
        raise click.ClickException(
            f'Profile "{dst}" already exists as "{existing_paths[0]}", which would not be replaced by'
            f' writing "{dst_config_filepath}". Use {"--no-sops" if sops else "--sops"} to overwrite it,'
            " or remove it first."
        )

    src_name, src_config = PlanetAuthFactory.load_auth_client_config_from_profile(src)
    src_config.lazy_load()
    new_data = dict(src_config.data() or {})
    # Hidden is for built-in templates.  User profiles are always listed.
    new_data.pop("_hidden", None)
    if auth_client_id:
        new_data["client_id"] = auth_client_id
    if auth_client_secret:
        new_data["client_secret"] = auth_client_secret
    new_data.update(_parse_set_values(set_values))

    auth_config = AuthClientConfig.from_dict(new_data)
    if prompt is None:
        prompt = sys.stdin.isatty()
    if prompt and not auth_config.is_complete():
        click.echo(f'Profile "{src_name}" is incomplete. Enter the missing settings for "{dst}".')
        auth_config = _prompt_for_missing_fields(auth_config)

    auth_config.set_path(dst_config_filepath)
    # No need to specify provider. The CLI is only concerned with the
    # default file based storage provider for now.
    # auth_config.auth_client().config().set_storage_provider()
    auth_config.save()
    click.echo(f'Created profile "{dst}" from "{src_name}" in "{dst_config_filepath}".', err=True)

    missing = auth_config.missing_required_fields()
    if missing:
        click.echo(
            f'Profile "{dst}" is incomplete. Missing required settings:\n'
            f"{_missing_fields_detail_text(missing)}\n"
            f"Supply them by repeating the copy with --force and"
            f' {_copy_options_for_missing_fields(missing)}, or by editing "{dst_config_filepath}".',
            err=True,
        )


@cmd_profile.command("check")
@click.argument("profile_name", required=False)
@click.option(
    "--online",
    is_flag=True,
    default=False,
    help="Also check that the auth server can be reached.  Only supported for OAuth profiles.",
)
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_profile_check(ctx, profile_name, online):
    """
    Check that an auth profile is complete and usable.

    Incomplete profiles may be used as templates for creating new profiles
    with `profile copy`, and some may be completed at runtime with options
    such as `--auth-client-id` and `--auth-client-secret`.  This command
    reports what settings a profile is missing.  If no profile is specified,
    the currently selected profile is checked.

    Exits with a non-zero status if the profile is not usable.
    """
    if not profile_name:
        profile_name = _selected_profile_name(ctx)

    ok, report = _check_profile(profile_name, online)
    click.echo(report)
    if not ok:
        sys.exit(1)


def _selected_profile_name(ctx) -> str:
    root_params = ctx.find_root().params
    return PlanetAuthUserConfigEnhanced().effective_conf_value(
        config_key=EnvironmentVariables.AUTH_PROFILE,
        override_value=root_params.get("auth_profile"),
        fallback_value=Builtins.builtin_default_profile_name(),
    )


def _check_profile(profile_name: str, online: bool) -> Tuple[bool, str]:
    try:
        normalized_name, auth_config = PlanetAuthFactory.load_auth_client_config_from_profile(profile_name)
        auth_config.lazy_load()
    except FileNotFoundError:
        return False, f'Profile "{profile_name}" was not found.'
    except AuthException as e:
        return False, f'Profile "{profile_name}" is not valid: {e}'

    try:
        auth_config.check_complete()
    except AuthClientConfigIncompleteException as e:
        report = (
            f'Profile "{normalized_name}" is incomplete. Missing required settings:\n'
            f"{_missing_fields_detail_text(e.missing_fields())}"
        )
        if Builtins.is_builtin_profile(normalized_name):
            report += (
                f"\nThis built-in profile is a template.  Create a profile from it with"
                f" `profile copy {normalized_name} <new profile name>`."
            )
        return False, report

    report = f'Profile "{normalized_name}" is complete.'
    if online:
        auth_client = AuthClient.from_config(auth_config)
        if not isinstance(auth_client, OidcAuthClient):
            return True, report + "\nOnline checks are not supported for this type of profile."
        auth_server = (auth_config.data() or {}).get("auth_server")
        try:
            auth_client.oidc_discovery()
        except Exception as e:  # pylint: disable=broad-exception-caught
            return False, report + f"\nFailed to reach the auth server {auth_server}: {e}"
        report += f"\nAuth server {auth_server} is reachable."
    return True, report


def _incomplete_profile_warning(profile_name: str, auth_config: AuthClientConfig) -> Optional[str]:
    try:
        auth_config.check_complete()
    except AuthClientConfigIncompleteException as e:
        return str(PlanetAuthFactory._incomplete_profile_exception(profile_name, e))
    return None


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
        normalized_profile_name, selected_config = PlanetAuthFactory.load_auth_client_config_from_profile(
            selected_profile
        )
        selected_config.lazy_load()
        selected_profile = normalized_profile_name
        warning = _incomplete_profile_warning(selected_profile, selected_config)
        if warning:
            click.echo(f"Warning: {warning}", err=True)

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
    if ctx.obj.get("AUTH"):
        print(f'Current: {ctx.obj["AUTH"].profile_name()}')
    else:
        print(f'Current: N/A ({ctx.obj.get("AUTH_INIT_ERROR")})')
    try:
        user_profile_config_file = PlanetAuthUserConfig()
        print(f"User Default: {user_profile_config_file.lazy_get(EnvironmentVariables.AUTH_PROFILE)}")
    except Exception:  #  as ex:
        # print(f'User Default: {ex}')
        print("User Default: N/A")

    print(f"Global Built-in Default: {Builtins.builtin_default_profile_name()}")
