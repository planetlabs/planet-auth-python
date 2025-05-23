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

from planet_auth import (
    Auth,
    AuthException,
    FileBackedPlanetLegacyApiKey,
    PlanetLegacyAuthClient,
    PlanetLegacyAuthClientConfig,
    StaticApiKeyAuthClient,
    StaticApiKeyAuthClientConfig,
)
from planet_auth_utils.plauth_factory import PlanetAuthFactory

from .options import (
    # opt_api_key,
    opt_password,
    opt_profile,
    opt_sops,
    opt_username,
    opt_yes_no,
)
from .util import recast_exceptions_to_click, post_login_cmd_helper


def _check_client_type_pllegacy(plauth_context: Auth):
    if not isinstance(plauth_context.auth_client(), PlanetLegacyAuthClient):
        raise click.ClickException(
            f'"legacy" auth commands can only be used with "{PlanetLegacyAuthClientConfig.meta()["client_type"]}" type auth profiles.'
            f' The current profile "{plauth_context.profile_name()}" is of type "{plauth_context.auth_client()._auth_client_config.meta()["client_type"]}".'
        )


def _check_client_type_pllegacy_for_click_ctx(click_ctx):
    _check_client_type_pllegacy(click_ctx.obj["AUTH"])


def _check_client_type_pllegacy_or_apikey_for_click_ctx(click_ctx):
    if not (
        isinstance(click_ctx.obj["AUTH"].auth_client(), PlanetLegacyAuthClient)
        or isinstance(click_ctx.obj["AUTH"].auth_client(), StaticApiKeyAuthClient)
    ):
        raise click.ClickException(
            "This command can only be used with "
            f'"{PlanetLegacyAuthClientConfig.meta()["client_type"]}" or "{StaticApiKeyAuthClientConfig.meta()["client_type"]}" '
            "type auth profiles. "
            f'The current profile "{click_ctx.obj["AUTH"].profile_name()}" is of type "{click_ctx.obj["AUTH"].auth_client()._auth_client_config.meta()["client_type"]}".'
        )


@click.group("legacy", invoke_without_command=True)
@click.pass_context
def cmd_pllegacy(ctx):
    """
    Planet legacy authentication commands.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)


@cmd_pllegacy.command("login")
@opt_profile(envvar=None)
@opt_password(hidden=False, envvar=None)
@opt_username(hidden=False, envvar=None)
# @opt_api_key(hidden=False, envvar=None)
@opt_sops()
@opt_yes_no()
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_pllegacy_login(ctx, auth_profile, username, password, sops, yes):
    """
    Perform an initial login using Planet's legacy authentication interfaces.
    """
    # Like the root login command, the expected behavior of the legacy "login" command is
    #   to do what it is told, not fall back to defaults and user prefs in unexpected ways.
    #   We ignore env vars and the config file.
    # root_cmd_auth_context = ctx.obj["AUTH"]
    override_auth_context = PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=auth_profile,
        # TODO?: API Key isn't consumed yet to create a client config with an API key that retains
        #  the knowledge that it was legacy protocol. We may never fix this as we are
        #  retiring the old auth protocol.  This can be accomplished with the root
        #  login command and an API key argument.
        # auth_api_key_opt=auth_api_key,
        # auth_username_opt=auth_username,
        # auth_password_opt=auth_password,
        use_env=False,
        use_configfile=False,
    )
    _check_client_type_pllegacy(override_auth_context)
    print(f"Logging in with authentication profile {override_auth_context.profile_name()}...")
    override_auth_context.login(
        allow_tty_prompt=True,
        username=username,
        password=password,
        # TODO: Should we support API key in login?
        #    The main purpose of the legacy method login() is to get
        #    the API key (and the JWT). Invoking login should force a login
    )
    print("Login succeeded.")  # Errors should throw.
    post_login_cmd_helper(override_auth_context=override_auth_context, use_sops=sops, prompt_pre_selection=yes)


@cmd_pllegacy.command("print-api-key")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_pllegacy_print_api_key(ctx):
    """
    Show the current API Key.  This command only applies to auth profiles
    that use simple API keys.
    """
    # We also support StaticApiKeyAuthClient in some cases where the user
    # directly provides an API key.  Such clients can use the legacy API
    # key, but lack the ability to obtain one.  This helps in our transition
    # away from the legacy auth protocol.
    _check_client_type_pllegacy_or_apikey_for_click_ctx(ctx)

    # Since API keys are static, we support them in the client config
    # and not just in the token file.
    if isinstance(ctx.obj["AUTH"].auth_client(), PlanetLegacyAuthClient):
        api_key = ctx.obj["AUTH"].auth_client().config().legacy_api_key()
        if api_key:
            print(api_key)
            return
    if isinstance(ctx.obj["AUTH"].auth_client(), StaticApiKeyAuthClient):
        api_key = ctx.obj["AUTH"].auth_client().config().api_key()
        if api_key:
            print(api_key)
            return

    saved_token = FileBackedPlanetLegacyApiKey(api_key_file=ctx.obj["AUTH"].token_file_path())
    print(saved_token.legacy_api_key())


@cmd_pllegacy.command("print-access-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_pllegacy_print_access_token(ctx):
    """
    Show the current legacy JWT access token.
    """
    _check_client_type_pllegacy_for_click_ctx(ctx)
    saved_token = FileBackedPlanetLegacyApiKey(api_key_file=ctx.obj["AUTH"].token_file_path())
    print(saved_token.legacy_jwt())
