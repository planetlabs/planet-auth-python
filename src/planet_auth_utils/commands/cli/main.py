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

from planet_auth import (
    Auth,
    AuthClientConfigIncompleteException,
    AuthException,
    setStructuredLogging,
    ObjectStorageProvider,
    ObjectStorageProvider_KeyType,
)
from planet_auth.constants import USER_CONFIG_FILE
from planet_auth.logging.auth_logger import getAuthLogger

from planet_auth_utils.plauth_factory import PlanetAuthFactory, ProfileConflictException
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
    opt_extra,
)
from .oauth_cmd import cmd_oauth
from .planet_legacy_auth_cmd import cmd_pllegacy
from .profile_cmd import cmd_profile
from .jwt_cmd import cmd_jwt
from .util import recast_exceptions_to_click, login_cmd_helper

auth_logger = getAuthLogger()


# These commands do not depend on the root command's auth context, or
# tolerate its absence, so that users may fix profile problems.
_CMDS_TOLERANT_OF_PROFILE_ERRORS = {"login", "oauth", "profile", "reset", "version"}


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

    try:
        ctx.obj["AUTH"] = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt=auth_profile,
            # token_file_opt=token_file,
        )
    except (AuthClientConfigIncompleteException, ProfileConflictException) as e:
        # Commands that manage profiles or perform their own auth context
        # initialization must remain usable so the user can fix the problem.
        if ctx.invoked_subcommand not in _CMDS_TOLERANT_OF_PROFILE_ERRORS:
            raise
        auth_logger.debug(msg=f"Deferring auth profile error for command {ctx.invoked_subcommand}: {e}")
        ctx.obj["AUTH"] = None
        ctx.obj["AUTH_INIT_ERROR"] = e


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
@opt_extra()
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError, ValueError)
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
    extra,
):
    """
    Perform an initial login.

    This command performs an initial login, obtains user authorization,
    and saves access tokens for the selected authentication profile.
    The specific process used depends on the selected options and
    authentication profile.

    Auth profile, client, and API key options given to this command are
    combined with those given to parent commands, and take priority.
    """
    # Options are consumed via the click context by login_auth_context().
    _ = (auth_profile, auth_api_key)
    login_cmd_helper(
        ctx,
        scope=scope,
        audience=audience,
        open_browser=open_browser,
        show_qr_code=show_qr_code,
        organization=organization,
        project=project,
        extra=extra,
        username=username,
        password=password,
        auth_client_id=auth_client_id,
        auth_client_secret=auth_client_secret,
        sops=sops,
        yes=yes,
    )


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
