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
import pathlib
from typing import Any, Callable, Optional

from planet_auth_utils.constants import EnvironmentVariables


_click_option_decorator_type = Callable[..., Any]


# TODO: Should we make "required" param universal for all options?
#     Maybe rather than being so prescriptive, we pass **kwargs to click options?
def opt_api_key(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_API_KEY
) -> _click_option_decorator_type:
    """
    Click option for specifying an API key
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--auth-api-key",
            type=str,
            envvar=envvar,
            help="Specify an API key.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_audience(
    default=None, hidden: bool = False, required=False, envvar: Optional[str] = EnvironmentVariables.AUTH_AUDIENCE
) -> _click_option_decorator_type:
    """
    Click option for specifying an OAuth token audience for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--audience",
            multiple=True,
            type=str,
            envvar=envvar,
            help="Token audiences.  Specify multiple options to set"
            " multiple audiences.  When set via environment variable, audiences"
            " should be white space delimited.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            required=required,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_client_id(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_CLIENT_ID
) -> _click_option_decorator_type:
    """
    Click option for specifying an OAuth client ID.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--auth-client-id",
            type=str,
            envvar=envvar,
            help="Specify the OAuth client ID.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_client_secret(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_CLIENT_SECRET
) -> _click_option_decorator_type:
    """
    Click option for specifying an OAuth client secret.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--auth-client-secret",
            type=str,
            envvar=envvar,
            help="Specify the OAuth client Secret.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_extra(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_EXTRA
) -> _click_option_decorator_type:
    """
    Click option for specifying extra options.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--extra",
            "-O",
            multiple=True,
            type=str,
            envvar=envvar,
            help="Specify an extra option.  Specify multiple options to specify"
            " multiple extra options.  The format of an option is <key>=<value>."
            " When set via environment variable, values should be delimited by"
            " whitespace.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_human_readable(default=False, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option to toggle raw / human-readable formatting.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--human-readable/--no-human-readable",
            "-H",
            help="Reformat fields to be human readable.",
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_issuer(
    default=None, hidden: bool = False, required=False, envvar: Optional[str] = EnvironmentVariables.AUTH_ISSUER
) -> _click_option_decorator_type:
    """
    Click option for specifying an OAuth token issuer for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--issuer",
            type=str,
            envvar=envvar,
            help="Token issuer.",
            default=default,
            show_envvar=bool(envvar),
            show_default=False,
            required=required,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_loglevel(
    default="INFO", hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_LOGLEVEL
) -> _click_option_decorator_type:
    """
    Click option for specifying a log level.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "-l",
            "--loglevel",
            envvar=envvar,
            help="Set the log level.",
            type=click.Choice(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], case_sensitive=False),
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_long(default=False, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option specifying that long or more detailed output should be produced.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "-l",
            "--long",
            help="Longer, more detailed output.",
            is_flag=True,
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_open_browser(default=True, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option for specifying whether opening a browser is permitted
    for the planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--open-browser/--no-open-browser",
            help="Allow/Suppress the automatic opening of a browser window.",
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_organization(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_ORGANIZATION
) -> _click_option_decorator_type:
    """
    Click option for specifying an Organization.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--organization",
            multiple=False,
            type=str,
            envvar=envvar,
            help="Organization to use when performing authentication.  When present, this option will be"
            " appended to authorization requests.  Not all implementations understand this option.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


# TODO -  Consider switching to click prompts where we current rely on the lower level planet_auth
#         to prompt the user. Currently, some of this IO is delegated to the planet_auth library.
#         I generally think user IO belongs with the app, and not the the library, but since the
#         lib also handles things like browser interaction this is not entirely easy to abstract
#         away.
def opt_password(
    default=None, hidden: bool = True, envvar: Optional[str] = EnvironmentVariables.AUTH_PASSWORD
) -> _click_option_decorator_type:
    """
    Click option for specifying a password for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--password",
            type=str,
            envvar=envvar,
            help="Password used for authentication.  May not be used by all authentication mechanisms.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,  # Primarily used by legacy auth.  OAuth2 is preferred, wherein we do not handle username/password.
        )(function)
        return function

    return decorator


def opt_profile(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_PROFILE
) -> _click_option_decorator_type:
    """
    Click option for specifying an auth profile for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--auth-profile",
            type=str,
            envvar=envvar,
            help="Select the client authentication profile to use.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            is_eager=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_project(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_PROJECT
) -> _click_option_decorator_type:
    """
    Click option for specifying a project ID.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--project",
            multiple=False,
            type=str,
            envvar=envvar,
            help="Project ID to use when performing authentication.  When present, this option will be"
            " appended to authorization requests.  Not all implementations understand this option.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_qr_code(default=False, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option for specifying whether a QR code should be displayed.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--show-qr-code/--no-show-qr-code",
            help="Control whether a QR code is displayed for the user.",
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_refresh(default=True, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option specifying a refresh should be attempted if applicable.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--refresh/--no-refresh",
            help="Automatically perform a credential refresh if required.",
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_token(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_TOKEN
) -> _click_option_decorator_type:
    """
    Click option for specifying a token literal.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--token",
            help="Token string.",
            default=default,
            type=str,
            # envvar=envvar,
            # show_envvar=bool(envvar)
            show_envvar=False,
            show_default=False,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_scope(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_SCOPE
) -> _click_option_decorator_type:
    """
    Click option for specifying an OAuth token scope for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--scope",
            multiple=True,
            type=str,
            envvar=envvar,
            help="Token scope.  Specify multiple options to specify"
            " multiple scopes.  When set via environment variable, scopes"
            " should be white space delimited.  Default value is determined"
            " by the selected auth profile.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_sops(default=False, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option specifying that SOPS should be used.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--sops/--no-sops",
            help="Use sops when creating new files where applicable."
            " The environment must be configured for SOPS to work by default.",
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_token_file(
    default=None, hidden: bool = False, envvar: Optional[str] = EnvironmentVariables.AUTH_TOKEN_FILE
) -> _click_option_decorator_type:
    """
    Click option for specifying a token file location for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--token-file",
            type=click.Path(exists=True, file_okay=True, readable=True, path_type=pathlib.Path),
            envvar=envvar,
            help="File containing a token.",
            default=default,
            show_envvar=False,  # Thinking about deprecated, so not encouraging.
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator


def opt_username(
    default=None, hidden: bool = True, envvar: Optional[str] = EnvironmentVariables.AUTH_USERNAME
) -> _click_option_decorator_type:
    """
    Click option for specifying a username for the
    planet_auth package's click commands.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--username",
            "--email",
            type=str,
            envvar=envvar,
            help="Username used for authentication.  May not be used by all authentication mechanisms.",
            default=default,
            show_envvar=bool(envvar),
            show_default=True,
            hidden=hidden,  # Primarily used by legacy auth.  OAuth2 is preferred, wherein we do not handle username/password.
        )(function)
        return function

    return decorator


def opt_yes_no(default=None, hidden: bool = False) -> _click_option_decorator_type:
    """
    Click option to bypass prompts with a yes or no selection.
    """

    def decorator(function) -> _click_option_decorator_type:
        function = click.option(
            "--yes/--no",
            "-y/-n",
            help='Skip user prompts with a "yes" or "no" selection.',
            default=default,
            show_default=True,
            hidden=hidden,
        )(function)
        return function

    return decorator
