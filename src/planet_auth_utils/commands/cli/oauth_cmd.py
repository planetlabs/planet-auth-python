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

from planet_auth import AuthException, FileBackedOidcCredential, OidcAuthClient

from .options import (
    opt_token_scope,
    opt_token_audience,
    opt_open_browser,
    opt_show_qr_code,
    opt_auth_organization,
    opt_auth_password,
    opt_auth_project,
    opt_auth_username,
    opt_auth_client_id,
    opt_auth_client_secret,
)
from .util import recast_exceptions_to_click, print_obj


@click.group("oauth", invoke_without_command=True)
@click.pass_context
def oauth_cmd_group(ctx):
    """
    Auth commands specific to OAuth authentication mechanisms.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    if not isinstance(ctx.obj["AUTH"].auth_client(), OidcAuthClient):
        raise click.ClickException("'oauth' auth command can only be used with OAuth type auth profiles.")


@oauth_cmd_group.command("login")
@opt_open_browser
@opt_show_qr_code
@opt_token_scope
@opt_token_audience()
@opt_auth_organization
@opt_auth_project
@opt_auth_username
@opt_auth_password
@opt_auth_client_id
@opt_auth_client_secret
@click.pass_context
@recast_exceptions_to_click(AuthException)
def oauth_do_login(
    ctx,
    scope,
    audience,
    open_browser,
    show_qr_code,
    organization,
    username,
    password,
    auth_client_id,
    auth_client_secret,
    project,
):
    """
    Perform an initial login using OAuth.
    """
    extra = {}
    if project:
        # Planet Labs OAuth extension to request a token for a particular project
        extra["project_id"] = project
    if organization:
        # Used by Auth0's OAuth implementation to support their concept of selecting
        # a particular organization at login when the user belongs to more than one.
        extra["organization"] = organization

    _ = ctx.obj["AUTH"].login(
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


@oauth_cmd_group.command("refresh")
@opt_token_scope
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_refresh(ctx, scope):
    """
    Obtain a new credential using the saved refresh token.

    It is possible to request a refresh token with scopes that are different
    than what is currently possessed, but you will never be granted
    more scopes than what the user has authorized.  This functionality
    is only supported for authentication mechanisms that support
    the concepts of separate (short-lived) access tokens and
    (long-lived) refresh tokens.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    if not saved_token.refresh_token():
        raise click.ClickException("No refresh_token found in " + str(saved_token.path()))

    saved_token.set_data(auth_client.refresh(saved_token.refresh_token(), scope).data())
    saved_token.save()


@oauth_cmd_group.command("list-scopes")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_list_scopes(ctx):
    """
    List available OAuth scopes.

    This command will query the auth server for available scopes that may be requested.
    """
    auth_client = ctx.obj["AUTH"].auth_client()
    available_scopes = auth_client.get_scopes()
    available_scopes.sort()
    if available_scopes:
        print_obj(available_scopes)
    else:
        print_obj([])


@oauth_cmd_group.command("validate-access-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_validate_access_token(ctx):
    """
    Validate the access token. Validation is performed by calling
    out to the auth provider's token introspection network service.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    validation_json = auth_client.validate_access_token_remote(saved_token.access_token())

    if not validation_json or not validation_json.get("active"):
        print_obj("INVALID")
        sys.exit(1)
    # print_obj("OK")
    print_obj(validation_json)


@oauth_cmd_group.command("validate-access-token-local")
@click.pass_context
@opt_token_audience()
@opt_token_scope
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_validate_access_token_local(ctx, audience, scope):
    """
    Validate the access token locally.

    When scopes are passed to the access token validator, the validator
    performs an "any of" check.  It will assert that any one of the scopes
    is present in the token. The validator does not assert that all scopes
    are present.

    It no scopes are passed to the validator, none are required.

    NOTICE:
        This functionality is not supported for all OAuth implementations.
        Access tokens are intended for consumption by resource servers,
        and may be opaque to the client.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    # Throws on error.
    validation_json = auth_client.validate_access_token_local(
        access_token=saved_token.access_token(), required_audience=audience, scopes_anyof=scope
    )
    print_obj(validation_json)


@oauth_cmd_group.command("validate-id-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_validate_id_token(ctx):
    """
    Validate the ID token. Validation is performed by calling
    out to the auth provider's token introspection network service.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    validation_json = auth_client.validate_id_token_remote(saved_token.id_token())

    if not validation_json or not validation_json.get("active"):
        print_obj("INVALID")
        sys.exit(1)
    # print_obj("OK")
    print_obj(validation_json)


@oauth_cmd_group.command("validate-id-token-local")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_validate_id_token_local(ctx):
    """
    Validate the ID token. This command validates the ID token locally,
    checking the token signature and claims against expected values.
    While validation is performed locally, network access is still
    required to obtain the signing keys from the auth provider.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    # Throws on error.
    validation_json = auth_client.validate_id_token_local(saved_token.id_token())
    # print_obj("OK")
    print_obj(validation_json)


@oauth_cmd_group.command("validate-refresh-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_validate_refresh_token(ctx):
    """
    Validate the refresh token. Validation is performed by calling
    out to the auth provider's token introspection network service.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    validation_json = auth_client.validate_refresh_token_remote(saved_token.refresh_token())

    if not validation_json or not validation_json.get("active"):
        print_obj("INVALID")
        sys.exit(1)
    # print_obj("OK")
    print_obj(validation_json)


@oauth_cmd_group.command("revoke-access-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_revoke_access_token(ctx):
    """
    Revoke the access token associated with the current profile.

    Revoking the access token does not revoke the refresh token, which will
    remain powerful.

    It should be noted that while this command revokes the access token with
    the auth services, access tokens are bearer tokens, and may still be
    accepted by some service endpoints.  Generally, it should be the case only
    less sensitive endpoints accept such tokens. High value services
    (such as admin services) should double verify tokens - insuring that they
    pass local validation, and checking with the auth provider that they have
    not been revoked.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    auth_client.revoke_access_token(saved_token.access_token())


@oauth_cmd_group.command("revoke-refresh-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_revoke_refresh_token(ctx):
    """
    Revoke the refresh token associated with the current profile.

    After the refresh token has been revoked, it will be necessary to login
    again to access other services.  Revoking the refresh token does not
    revoke the current access token, which may remain potent until its
    natural expiration time if not also revoked.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    auth_client.revoke_refresh_token(saved_token.refresh_token())


@oauth_cmd_group.command("userinfo")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_user_info(ctx):
    """
    Look up user information from the auth server using the access token.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    userinfo_json = auth_client.userinfo_from_access_token(saved_token.access_token())

    # print_obj("OK")
    print_obj(userinfo_json)


@oauth_cmd_group.command("print-access-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def do_print_access_token(ctx):
    """
    Show the OAuth access token used by the currently selected authentication
    profile.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    # Not using object print for token printing. We don't want object quoting and escaping.
    # print_obj(saved_token.access_token())
    # TODO: refresh if needed.
    print(saved_token.access_token())
