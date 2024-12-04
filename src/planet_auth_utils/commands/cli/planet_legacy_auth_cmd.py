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
import sys

from planet_auth import (
    AuthException,
    FileBackedPlanetLegacyApiKey,
    PlanetLegacyAuthClient,
    PlanetLegacyAuthClientConfig,
)

from .options import opt_auth_password, opt_auth_username
from .util import recast_exceptions_to_click


@click.group("legacy", invoke_without_command=True)
@click.pass_context
def pllegacy_auth_cmd_group(ctx):
    """
    Auth commands specific to Planet legacy authentication mechanisms.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    if not isinstance(ctx.obj["AUTH"].auth_client(), PlanetLegacyAuthClient):
        raise click.ClickException(
            f'"legacy" auth command can only be used with "{PlanetLegacyAuthClientConfig.meta()["client_type"]}" type auth profiles.'
            f' The current profile "{ctx.obj["AUTH"].profile_name()}" is of type "{ctx.obj["AUTH"].auth_client()._auth_client_config.meta()["client_type"]}".'
        )


@pllegacy_auth_cmd_group.command("login")
@opt_auth_password
@opt_auth_username
@click.pass_context
def pllegacy_do_login(ctx, username, password):
    """
    Perform an initial login using Planet's legacy authentication interfaces.
    """
    _ = ctx.obj["AUTH"].login(
        allow_tty_prompt=True,
        username=username,
        password=password,
    )
    print("Login succeeded.")  # Errors should throw.


@pllegacy_auth_cmd_group.command("print-api-key")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_print_api_key(ctx):
    """
    Show the API Key used by the currently selected authentication profile.
    Auth profiles that do not use API keys will not support this command.
    """
    saved_token = FileBackedPlanetLegacyApiKey(api_key_file=ctx.obj["AUTH"].token_file_path())
    # Not using object print for API keys printing. We don't want object quoting and escaping.
    # print_obj(saved_token.legacy_api_key())
    print(saved_token.legacy_api_key())


@pllegacy_auth_cmd_group.command("print-access-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_print_access_token(ctx):
    """
    Show the legacy JWT.
    Auth profiles that do not use legacy JWTs will not support this command.
    """
    saved_token = FileBackedPlanetLegacyApiKey(api_key_file=ctx.obj["AUTH"].token_file_path())
    print(saved_token.legacy_jwt())
