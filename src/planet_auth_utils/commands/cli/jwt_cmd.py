# Copyright 2025 Planet Labs PBC.
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
import pathlib
import sys
import textwrap
import time
import typing

from planet_auth import (
    AuthException,
    TokenValidator,
    OidcMultiIssuerValidator,
)
from planet_auth.util import custom_json_class_dumper

from .options import (
    opt_audience,
    opt_issuer,
    opt_token,
    opt_token_file,
    opt_human_readable,
)
from .util import recast_exceptions_to_click


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


def json_dumps_for_jwt_dict(data: dict, human_readable: bool, indent: int = 2):
    if human_readable:
        return json.dumps(_jwt_human_dumps(data), indent=indent, sort_keys=True, default=custom_json_class_dumper)
    else:
        return json.dumps(data, indent=2, sort_keys=True)


def print_jwt_parts(raw, header, body, signature, human_readable):
    if raw:
        print(f"RAW:\n    {raw}\n")

    if header:
        print(
            f'HEADER:\n{textwrap.indent(json_dumps_for_jwt_dict(data=header, human_readable=human_readable), prefix="    ")}\n'
        )

    if body:
        print(
            f'BODY:\n{textwrap.indent(json_dumps_for_jwt_dict(body, human_readable=human_readable), prefix="    ")}\n'
        )

    if signature:
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

        print(f'SIGNATURE:\n{textwrap.indent(pretty_hex_signature, prefix="    ")}\n')


def hazmat_print_jwt(token_str, human_readable):
    print("UNTRUSTED JWT Decoding\n")
    if token_str:
        (hazmat_header, hazmat_body, hazmat_signature) = TokenValidator.hazmat_unverified_decode(token_str)
        print_jwt_parts(
            raw=token_str,
            header=hazmat_header,
            body=hazmat_body,
            signature=hazmat_signature,
            human_readable=human_readable,
        )


@click.group("jwt", invoke_without_command=True)
@click.pass_context
def cmd_jwt(ctx):
    """
    JWT utility for working with tokens.  These functions are primarily targeted
    towards debugging usage.  Many of the functions do not perform token validation.
    THE CONTENTS OF UNVALIDATED TOKENS MUST BE TREATED AS UNTRUSTED AND POTENTIALLY
    MALICIOUS.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(0)


def _get_token_or_fail(token_opt: typing.Optional[str], token_file_opt: typing.Optional[pathlib.Path]):
    if token_opt:
        token = token_opt
    elif token_file_opt:
        with open(token_file_opt, mode="r", encoding="UTF-8") as file_r:
            token = file_r.read()
    else:
        # click.echo(ctx.get_help())
        # click.echo()
        raise click.UsageError("A token must be provided.")
    return token


@cmd_jwt.command("decode")
@click.pass_context
@opt_human_readable()
@opt_token()
@opt_token_file()
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_jwt_decode(ctx, token: str, token_file: pathlib.Path, human_readable):
    """
    Decode a JWT token WITHOUT PERFORMING ANY VALIDATION.
    """
    token_to_print = _get_token_or_fail(token_opt=token, token_file_opt=token_file)
    hazmat_print_jwt(token_str=token_to_print, human_readable=human_readable)


@cmd_jwt.command("validate-oauth")
@click.pass_context
@opt_human_readable()
@opt_token()
@opt_token_file()
@opt_audience()
@opt_issuer()
@recast_exceptions_to_click(AuthException, FileNotFoundError)
def cmd_jwt_validate_oauth(ctx, token, token_file, audience, issuer, human_readable):
    """
    Perform signature validation on an RFC 9068 compliant JWT token.
    The `iss` and `aud` claims will be used to look up signing keys
    using OAuth2/OIDC discovery protocols and perform basic validation
    checks.

    This command performs only basic signature verification and token validity
    checks.  For checks against auth server token revocation lists, see the `oauth`
    command.  For deeper checks specific to the claims and structure of
    Identity or Access tokens, see the `oauth` command.

    WARNING:\n
    THIS TOOL IS ABSOLUTELY INAPPROPRIATE FOR PRODUCTION TRUST USAGE.  This is a
    development and debugging utility.  The default behavior to inspect the token
    for issuer and audience information used to validate the token is wholly
    incorrect for a production use case.  The decision of which issuers to
    trust with what audiences MUST be controlled by the service operator.
    """
    token_to_validate = _get_token_or_fail(token_opt=token, token_file_opt=token_file)
    (hazmat_header, hazmat_body, hazmat_signature) = TokenValidator.hazmat_unverified_decode(token_to_validate)

    if issuer:
        validation_iss = issuer
    else:
        if not hazmat_body.get("iss"):
            raise click.BadParameter(
                "The provided token does not contain an `iss` claim.  Is the provided JWT RFC 9068 compliant?"
            )
        validation_iss = hazmat_body.get("iss")

    if audience:
        validation_aud = audience
    else:
        if not hazmat_body.get("aud"):
            raise click.BadParameter(
                "The provided token does not contain an `aud` claim.  Is the provided JWT RFC 9068 compliant?"
            )
        hazmat_aud = hazmat_body.get("aud")
        if isinstance(hazmat_aud, list):
            validation_aud = hazmat_aud[0]
        else:
            validation_aud = hazmat_aud

    validator = OidcMultiIssuerValidator.from_auth_server_urls(
        trusted_auth_server_urls=[validation_iss], audience=validation_aud, log_result=False
    )
    validated_body, _ = validator.validate_access_token(token_to_validate, do_remote_revocation_check=False)
    # Validation throws on error
    click.echo("TOKEN OK")
    print_jwt_parts(
        raw=token_to_validate,
        header=hazmat_header,
        body=validated_body,
        signature=hazmat_signature,
        human_readable=human_readable,
    )


@cmd_jwt.command("validate-rs256", hidden=True)
@click.pass_context
@opt_human_readable()
@opt_token()
@opt_token_file()
@recast_exceptions_to_click(AuthException, FileNotFoundError, NotImplementedError)
def cmd_jwt_validate_rs256(ctx, token, token_file, human_readable):
    """
    Validate a JWT signed with a RS256 signature
    """
    # token_to_validate = _get_token_or_fail(token_opt=token, token_file_opt=token_file)
    raise NotImplementedError("Command not implemented")


@cmd_jwt.command("validate-hs512", hidden=True)
@click.pass_context
@opt_human_readable()
@opt_token()
@opt_token_file()
@recast_exceptions_to_click(AuthException, FileNotFoundError, NotImplementedError)
def cmd_jwt_validate_hs512(ctx, token, token_file, human_readable):
    """
    Validate a JWT signed with a HS512 signature
    """
    # token_to_validate = _get_token_or_fail(token_opt=token, token_file_opt=token_file)
    raise NotImplementedError("Command not implemented")
