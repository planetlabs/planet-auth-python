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
import logging
import importlib.metadata
import sys
import time

from planet_auth import Auth, AuthException, setStructuredLogging, ObjectStorageProvider, ObjectStorageProvider_KeyType
from planet_auth.constants import USER_CONFIG_FILE

from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.profile import Profile

from .options import (
    opt_organization,
    opt_project,
    opt_profile,
    opt_client_id,
    opt_client_secret,
    opt_api_key,
    opt_username,
    opt_password,
    opt_loglevel,
    opt_open_browser,
    opt_qr_code,
    opt_sops,
    opt_audience,
    opt_scope,
    opt_yes_no,
)
from .oauth_cmd import cmd_oauth
from .planet_legacy_auth_cmd import cmd_pllegacy
from .profile_cmd import cmd_profile
from .jwt_cmd import cmd_jwt
from .util import recast_exceptions_to_click, post_login_cmd_helper


@click.group("plauth", invoke_without_command=True, help="Planet authentication utility")
@opt_loglevel()
@opt_profile()
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_plauth(ctx, loglevel, auth_profile):
    """
    Planet Auth Utility commands
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    # cli_logger = logging.getLogger("plauth-logger")
    # setPyLoggerForAuthLogger(cli_logger)
    setStructuredLogging(nested_key=None)
    logging.basicConfig(level=loglevel)

    ctx.ensure_object(dict)

    ctx.obj["AUTH"] = PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=auth_profile,
        # token_file_opt=token_file,
    )


@click.group("plauth", invoke_without_command=True, help="Embedded PLAuth advanced authentication utility")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_plauth_embedded(ctx):
    """
    Planet Auth Utility commands

    Embeddable version of the Planet Auth Client root command.
    The embedded command differs from the stand-alone command in that it
    expects the context to be instantiated and options to be handled by
    the parent command.  The [planet_auth.Auth][] library context _must_
    be saved to the object field `AUTH` in the click context object.

    See [planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context][]
    for user-friendly auth client context initialization.

    See [examples](/examples/#embedding-the-click-auth-command).
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    ctx.ensure_object(dict)

    if not isinstance(ctx.obj.get("AUTH"), Auth):
        raise click.ClickException(
            "INTERNAL ERROR:"
            "  The Auth context is expected to be created by the caller when using the embedded plauth command."
            "  This is a programming error, and must be fixed by the developer."
            "  See developer documentation."
        )


@cmd_plauth.command("version")
def cmd_plauth_version():
    """
    Show the version of planet auth components.
    """

    def _pkg_display_version(pkg_name):
        try:
            return importlib.metadata.version(pkg_name)
        except importlib.metadata.PackageNotFoundError:
            return "N/A"

    # Well known packages with built-in profile configs we commonly use.
    print(f"planet-auth : {_pkg_display_version('planet-auth')}")
    print(f"planet-auth-config : {_pkg_display_version('planet-auth-config')}")
    print(f"planet : {_pkg_display_version('planet')}")


@cmd_plauth.command("reset")
def cmd_plauth_reset():
    """
    Reset saved auth state.

    Old auth state is not deleted. It is moved aside and preserved.
    """
    save_tag = time.strftime("%Y-%m-%d-%H%M%S")

    # The CLI only supports the default storage provider right now.
    storage_provider = ObjectStorageProvider._default_storage_provider()

    user_conf_objkey = ObjectStorageProvider_KeyType(USER_CONFIG_FILE)
    if storage_provider.obj_exists(user_conf_objkey):
        user_conf_objkey_offname = ObjectStorageProvider_KeyType(USER_CONFIG_FILE + f"-{save_tag}")
        storage_provider.obj_rename(user_conf_objkey, user_conf_objkey_offname)

    profile_dir_objkey = ObjectStorageProvider_KeyType(Profile.profile_root())
    if storage_provider.obj_exists(profile_dir_objkey):
        profile_dir_objkey_offname = ObjectStorageProvider_KeyType(Profile.profile_root().name + f"-{save_tag}")
        storage_provider.obj_rename(profile_dir_objkey, profile_dir_objkey_offname)


@cmd_plauth.command("login")
@opt_open_browser()
@opt_qr_code()
@opt_scope()
@opt_audience()
@opt_organization()
@opt_project()
@opt_profile()
@opt_client_id()
@opt_client_secret()
@opt_api_key()
@opt_username()
@opt_password()
@opt_sops()
@opt_yes_no()
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def cmd_plauth_login(
    ctx,
    scope,
    audience,
    open_browser,
    show_qr_code,
    organization,
    project,
    auth_profile,
    auth_client_id,
    auth_client_secret,
    auth_api_key,
    username,
    password,
    sops,
    yes,
):
    """
    Perform an initial login.

    This command performs an initial login, obtains user authorization,
    and saves access tokens for the selected authentication profile.
    The specific process used depends on the selected options and
    authentication profile.
    """
    extra = {}
    if project:
        # Planet Labs OAuth extension to request a token for a particular project
        extra["project_id"] = project
    if organization:
        # Used by Auth0's OAuth implementation to support their concept of selecting
        # a particular organization at login when the user belongs to more than one.
        extra["organization"] = organization

    # Arguments to login commands may imply an override to the default/root
    # command auth provider in a way that is different from what we expect
    # in most non-root commands.
    # root_cmd_auth_context = ctx.obj["AUTH"]
    override_auth_context = PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=auth_profile,
        auth_client_id_opt=auth_client_id,
        auth_client_secret_opt=auth_client_secret,
        auth_api_key_opt=auth_api_key,
        # auth_username_opt=auth_username,
        # auth_password_opt=auth_password,
    )

    print(f"Logging in with authentication profile {override_auth_context.profile_name()}...")
    _ = override_auth_context.login(
        requested_scopes=scope,
        requested_audiences=audience,
        allow_open_browser=open_browser,
        allow_tty_prompt=True,
        display_qr_code=show_qr_code,
        username=username,
        password=password,
        client_id=auth_client_id,
        client_secret=auth_client_secret,
        extra=extra,
    )
    print("Login succeeded.")  # Errors should throw.

    post_login_cmd_helper(override_auth_context=override_auth_context, use_sops=sops, prompt_pre_selection=yes)


cmd_plauth.add_command(cmd_oauth)
cmd_plauth.add_command(cmd_pllegacy)
cmd_plauth.add_command(cmd_profile)
cmd_plauth.add_command(cmd_jwt)

cmd_plauth_embedded.add_command(cmd_oauth)
cmd_plauth_embedded.add_command(cmd_pllegacy)
cmd_plauth_embedded.add_command(cmd_profile)
cmd_plauth_embedded.add_command(cmd_jwt)
cmd_plauth_embedded.add_command(cmd_plauth_login)
cmd_plauth_embedded.add_command(cmd_plauth_version)


if __name__ == "__main__":
    cmd_plauth()  # pylint: disable=E1120
