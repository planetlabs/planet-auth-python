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
import json
import sys
import textwrap
import time

from planet_auth import (
    AuthException,
    FileBackedOidcCredential,
    OidcAuthClient,
    ExpiredTokenException,
    ClientCredentialsAuthClientBase,
    TokenValidator,
)
from planet_auth.util import custom_json_class_dumper

from .options import (
    opt_audience,
    opt_client_id,
    opt_client_secret,
    opt_human_readable,
    opt_open_browser,
    opt_organization,
    opt_password,
    opt_project,
    opt_refresh,
    opt_scope,
    opt_show_qr_code,
    opt_sops,
    opt_username,
)
from .util import recast_exceptions_to_click, post_login_cmd_helper, print_obj


class _jwt_human_dumps:
    """
    Wrapper object for controlling the json.dumps behavior of JWTs so that
    we can display a version different from what is stored in memory.

    For pretty printing JWTs, we convert timestamps into
    human-readable strings.
    """

    def __init__(self, data):
        self._data = data

    def __json_pretty_dumps__(self):
        def _human_timestamp_iso(d):
            for key, value in list(d.items()):
                if key in ["iat", "exp", "nbf"] and isinstance(value, int):
                    fmt_time = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(value))
                    if (key == "exp") and (d[key] < time.time()):
                        fmt_time += " (Expired)"
                    d[key] = fmt_time
                elif isinstance(value, dict):
                    _human_timestamp_iso(value)
            return d

        json_dumps = self._data.copy()
        _human_timestamp_iso(json_dumps)
        return json_dumps


def _json_dumps_for_jwt_dict(data: dict, human_readable: bool):
    if human_readable:
        return json.dumps(_jwt_human_dumps(data), indent=2, sort_keys=True, default=custom_json_class_dumper)
    else:
        return json.dumps(data, indent=2, sort_keys=True)


def _print_jwt(token_str, human_readable):
    print("Untrusted JWT Decoding\n")
    print(f"RAW:\n    {token_str}\n")
    if token_str:
        (header, body, signature) = TokenValidator.unverified_decode(token_str)
        pretty_hex_signature = ""
        i = 0
        for c in signature:
            if i == 0:
                pass
            elif (i % 16) != 0:
                pretty_hex_signature += ":"
            else:
                pretty_hex_signature += "\n"

            pretty_hex_signature += "{:02x}".format(c)
            i += 1

        print(
            f'HEADER:\n{textwrap.indent(_json_dumps_for_jwt_dict(data=header, human_readable=human_readable), prefix="    ")}\n'
        )
        print(
            f'BODY:\n{textwrap.indent(_json_dumps_for_jwt_dict(body, human_readable=human_readable), prefix="    ")}\n'
        )
        print(f'SIGNATURE:\n{textwrap.indent(pretty_hex_signature, prefix="    ")}\n')


def _check_client_type(ctx):
    if not isinstance(ctx.obj["AUTH"].auth_client(), OidcAuthClient):
        raise click.ClickException(
            f'"oauth" auth commands can only be used with OAuth type auth profiles.'
            f' The current profile "{ctx.obj["AUTH"].profile_name()}" is of type "{ctx.obj["AUTH"].auth_client()._auth_client_config.meta()["client_type"]}".'
        )


@click.group("oauth", invoke_without_command=True)
@click.pass_context
def cmd_oauth(ctx):
    """
    Auth commands specific to OAuth authentication mechanisms.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    _check_client_type(ctx)


@cmd_oauth.command("login")
@opt_open_browser
@opt_show_qr_code
@opt_scope
@opt_audience()
@opt_organization
@opt_project
@opt_username()
@opt_password()
@opt_client_id
@opt_client_secret
@opt_sops
@click.pass_context
@recast_exceptions_to_click(AuthException)
def cmd_oauth_login(
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
    sops,
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

    current_auth_context = ctx.obj["AUTH"]
    current_auth_context.login(
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
        override_auth_context=current_auth_context,
        use_sops=sops,
    )


@cmd_oauth.command("refresh")
@opt_scope
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_refresh(ctx, scope):
    """
    Obtain a new credential using the saved refresh token.

    It is possible to request a refresh token with scopes that are different
    from what is currently possessed, but you will never be granted
    more scopes than what the user has authorized.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    if not saved_token.refresh_token():
        raise click.ClickException("No refresh_token found in " + str(saved_token.path()))

    saved_token.set_data(auth_client.refresh(saved_token.refresh_token(), scope).data())
    saved_token.save()


@cmd_oauth.command("list-scopes")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_list_scopes(ctx):
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


@cmd_oauth.command("validate-access-token")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_validate_access_token_remote(ctx, human_readable):
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
    # print_obj(validation_json)
    print(_json_dumps_for_jwt_dict(data=validation_json, human_readable=human_readable))


@cmd_oauth.command("validate-access-token-local")
@click.pass_context
@opt_audience()
@opt_scope
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_validate_access_token_local(ctx, audience, scope, human_readable):
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
    # print_obj(validation_json)
    print(_json_dumps_for_jwt_dict(data=validation_json, human_readable=human_readable))


@cmd_oauth.command("validate-id-token")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_validate_id_token_remote(ctx, human_readable):
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
    # print_obj(validation_json)
    print(_json_dumps_for_jwt_dict(data=validation_json, human_readable=human_readable))


@cmd_oauth.command("validate-id-token-local")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_validate_id_token_local(ctx, human_readable):
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
    # print_obj(validation_json)
    print(_json_dumps_for_jwt_dict(data=validation_json, human_readable=human_readable))


@cmd_oauth.command("validate-refresh-token")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_validate_refresh_token_remote(ctx, human_readable):
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
    # print_obj(validation_json)
    print(_json_dumps_for_jwt_dict(data=validation_json, human_readable=human_readable))


@cmd_oauth.command("revoke-access-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_revoke_access_token(ctx):
    """
    Revoke the current access token.

    Revoking the access token does not revoke the refresh token, which will
    remain powerful.

    It should be noted that while this command revokes the access token with
    the auth services, access tokens are bearer tokens, and may still be
    accepted by some service endpoints. It is up to each service whether
    access tokens are accepted as bearer tokens, or double verified against
    the auth services.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    auth_client.revoke_access_token(saved_token.access_token())


@cmd_oauth.command("revoke-refresh-token")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_revoke_refresh_token(ctx):
    """
    Revoke the current refresh token.

    After the refresh token has been revoked, it will be necessary to login
    again to access other services.  Revoking the refresh token does not
    revoke the current access token, which may remain potent until its
    natural expiration time if not also revoked.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    auth_client.revoke_refresh_token(saved_token.refresh_token())


@cmd_oauth.command("userinfo")
@click.pass_context
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_userinfo(ctx):
    """
    Look up user information from the auth server using the access token.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    auth_client = ctx.obj["AUTH"].auth_client()
    saved_token.load()
    userinfo_json = auth_client.userinfo_from_access_token(saved_token.access_token())

    # print_obj("OK")
    print_obj(userinfo_json)


@cmd_oauth.command("print-access-token")
@click.pass_context
@opt_refresh
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_print_access_token(ctx, refresh):
    """
    Show the current OAuth access token.  Stale tokens will be automatically refreshed.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    saved_token.load()

    if refresh:
        auth_client = ctx.obj["AUTH"].auth_client()
        try:
            _ = auth_client.validate_access_token_local(access_token=saved_token.access_token())
        except ExpiredTokenException:
            # Client Credentials grant clients do not use a refresh token to refresh,
            # they re-login, which in their case is not user interactive.
            if saved_token.refresh_token():
                new_token = auth_client.refresh(saved_token.refresh_token())
            elif isinstance(auth_client, ClientCredentialsAuthClientBase):
                new_token = auth_client.login()
            else:
                raise click.ClickException("Cannot refresh expired token")  # pylint: disable=W0707

            saved_token.set_data(new_token.data())
            saved_token.save()

    # Not using object print for token printing. We don't want object quoting and escaping.
    # print_obj(saved_token.access_token())
    print(saved_token.access_token())


@cmd_oauth.command("decode-access-token")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_decode_jwt_access_token(ctx, human_readable):
    """
    Decode a JWT access token locally and display its contents.  NO
    VALIDATION IS PERFORMED.  This function is intended for local
    debugging purposes.  Note: Access tokens need not be JWTs.
    This function will not work for authorization servers that issue
    access tokens in other formats.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    _print_jwt(saved_token.access_token(), human_readable=human_readable)


@cmd_oauth.command("decode-id-token")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_decode_jwt_id_token(ctx, human_readable):
    """
    Decode a JWT ID token locally and display its contents.  NO
    VALIDATION IS PERFORMED.  This function is intended for local
    debugging purposes.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    _print_jwt(saved_token.id_token(), human_readable=human_readable)


@cmd_oauth.command("decode-refresh-token")
@click.pass_context
@opt_human_readable
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_oauth_decode_jwt_refresh_token(ctx, human_readable):
    """
    Decode a JWT refresh token locally and display its contents.  NO
    VALIDATION IS PERFORMED.  This function is intended for local
    debugging purposes.  Note: Refresh tokens need not be JWTs.
    This function will not work for authorization servers that issue
    refresh tokens in other formats.
    """
    saved_token = FileBackedOidcCredential(None, ctx.obj["AUTH"].token_file_path())
    _print_jwt(saved_token.refresh_token(), human_readable=human_readable)
