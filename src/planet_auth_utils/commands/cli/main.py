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
import pkg_resources
import sys

from planet_auth import Auth, AuthException

from planet_auth_utils.plauth_factory import PlanetAuthFactory

from .options import (
    opt_auth_organization,
    opt_auth_project,
    opt_auth_profile,
    opt_auth_client_id,
    opt_auth_client_secret,
    opt_auth_api_key,
    opt_auth_username,
    opt_auth_password,
    opt_loglevel,
    opt_open_browser,
    opt_show_qr_code,
    opt_sops,
    opt_token_audience,
    opt_token_file,
    opt_token_scope,
)
from .oauth_cmd import oauth_cmd_group
from .planet_legacy_auth_cmd import pllegacy_auth_cmd_group
from .profile_cmd import profile_cmd_group
from .util import recast_exceptions_to_click, post_login_cmd_helper


@click.group("plauth", invoke_without_command=True, help="Planet authentication utility")
@opt_loglevel
@opt_auth_profile
@opt_token_file  # Remove?  The interactions with changing the profile in login are not great.
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def plauth_cmd_group(ctx, loglevel, auth_profile, token_file):
    """
    Planet Auth Utility commands
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    logging.basicConfig(level=loglevel)

    ctx.ensure_object(dict)

    ctx.obj["AUTH"] = PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=auth_profile,
        token_file_opt=token_file,
    )


@click.group("plauth", invoke_without_command=True, help="Planet authentication utility")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def embedded_plauth_cmd_group(ctx):
    """
    Planet Auth Utility commands

    Embeddable version of the Planet Auth Client root command.
    The embedded command differs from the stand-alone command in that it
    expects the context to be instantiated and options to be handled by
    the parent command.  See [PlanetAuthFactory.initialize_auth_client_context][]
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


@plauth_cmd_group.command("version")
def do_version():
    """
    Show the version of planet auth components.
    """
    print("planet-auth         : {}".format(pkg_resources.get_distribution("planet-auth").version))


@plauth_cmd_group.command("login")
@opt_open_browser
@opt_show_qr_code
@opt_token_scope
@opt_token_audience()
@opt_auth_organization
@opt_auth_project
@opt_auth_profile
@opt_auth_client_id
@opt_auth_client_secret
@opt_auth_api_key
@opt_auth_username
@opt_auth_password
@opt_sops
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError, PermissionError)
def do_login(
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
):
    """
    Perform an initial login, obtain user authorization, and save access
    tokens for the selected authentication profile.  The specific process
    and supported options depends on the auth method selected.
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
    current_auth_context = ctx.obj["AUTH"]
    override_auth_context = PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=auth_profile,
        auth_client_id_opt=auth_client_id,
        auth_client_secret_opt=auth_client_secret,
        auth_api_key_opt=auth_api_key,
        # auth_username_opt=auth_username,
        # auth_password_opt=auth_password,
    )

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

    post_login_cmd_helper(
        override_auth_context=override_auth_context,
        current_auth_context=current_auth_context,
        use_sops=sops,
    )


plauth_cmd_group.add_command(oauth_cmd_group)
plauth_cmd_group.add_command(pllegacy_auth_cmd_group)
plauth_cmd_group.add_command(profile_cmd_group)

embedded_plauth_cmd_group.add_command(oauth_cmd_group)
embedded_plauth_cmd_group.add_command(pllegacy_auth_cmd_group)
embedded_plauth_cmd_group.add_command(profile_cmd_group)
embedded_plauth_cmd_group.add_command(do_login)
embedded_plauth_cmd_group.add_command(do_version)


if __name__ == "__main__":
    plauth_cmd_group()  # pylint: disable=E1120