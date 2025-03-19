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
import pathlib

from planet_auth_utils.constants import EnvironmentVariables


def opt_api_key(function):
    """
    Click option for specifying an API key
    """
    function = click.option(
        "--auth-api-key",
        type=str,
        envvar=EnvironmentVariables.AUTH_API_KEY,
        help="Specify an API key.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function


def opt_client_id(function):
    """
    Click option for specifying an OAuth client ID.
    """
    function = click.option(
        "--auth-client-id",
        type=str,
        envvar=EnvironmentVariables.AUTH_CLIENT_ID,
        help="Specify the OAuth client ID.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function


def opt_client_secret(function):
    """
    Click option for specifying an OAuth client secret.
    """
    function = click.option(
        "--auth-client-secret",
        type=str,
        envvar=EnvironmentVariables.AUTH_CLIENT_SECRET,
        help="Specify the OAuth client Secret.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function


def opt_profile(function):
    """
    Click option for specifying an auth profile for the
    planet_auth package's click commands.
    """
    function = click.option(
        "--auth-profile",
        type=str,
        envvar=EnvironmentVariables.AUTH_PROFILE,
        help="Select the client profile to use.  User created profiles are "
        " defined by creating a subdirectory ~/.planet/.  Additionally, a number of"
        ' built-in profiles are understood.  See the "profile list" command'
        " for defined profiles.  The auth profile controls how the software"
        " interacts with authentication services, as well as how it"
        " authenticates to other APIs.  If this option is not set,"
        " a profile will be selected according to environment variables or"
        ' a preference registered with the "profile set" command.',
        default=None,
        show_envvar=True,
        show_default=True,
        is_eager=True,
    )(function)
    return function


def opt_organization(function):
    """
    Click option for specifying an Organization.
    """
    function = click.option(
        "--organization",
        multiple=False,
        type=str,
        envvar=EnvironmentVariables.AUTH_ORGANIZATION,
        help="Organization to use when performing authentication.  When present, this option will be"
        " appended to authorization requests.  Not all implementations understand this option.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function


def opt_project(function):
    """
    Click option for specifying a project ID.
    """
    function = click.option(
        "--project",
        multiple=False,
        type=str,
        # envvar=EnvironmentVariables.AUTH_PROJECT,
        help="Project ID to use when performing authentication.  When present, this option will be"
        " appended to authorization requests.  Not all implementations understand this option.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function


# TODO -  Consider switching to click prompts where we current rely on the lower level planet_auth
#         to prompt the user. Currently, some of this IO is delegated to the planet_auth library.
#         I generally think user IO belongs with the app, and not the the library, but since the
#         lib also handles things like browser interaction this is not entirely easy to abstract
#         away.
def opt_password(hidden=True):
    def decorator(function):
        """
        Click option for specifying a password for the
        planet_auth package's click commands.
        """
        function = click.option(
            "--password",
            type=str,
            envvar=EnvironmentVariables.AUTH_PASSWORD,
            help="Password used for authentication.  May not be used by all authentication mechanisms.",
            default=None,
            show_envvar=True,
            show_default=True,
            hidden=hidden,  # Primarily used by legacy auth.  OAuth2 is preferred, wherein we do not handle username/password.
        )(function)
        return function

    return decorator


def opt_username(hidden=True):
    def decorator(function):
        """
        Click option for specifying a username for the
        planet_auth package's click commands.
        """
        function = click.option(
            "--username",
            "--email",
            type=str,
            envvar=EnvironmentVariables.AUTH_USERNAME,
            help="Username used for authentication.  May not be used by all authentication mechanisms.",
            default=None,
            show_envvar=True,
            show_default=True,
            hidden=hidden,  # Primarily used by legacy auth.  OAuth2 is preferred, wherein we do not handle username/password.
        )(function)
        return function

    return decorator


def opt_loglevel(function):
    """
    Click option for specifying a log level.
    """
    function = click.option(
        "-l",
        "--loglevel",
        envvar=EnvironmentVariables.AUTH_LOGLEVEL,
        help="Set the log level.",
        type=click.Choice(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], case_sensitive=False),
        default="INFO",
        show_envvar=True,
        show_default=True,
    )(function)
    return function


def opt_yes_no(function):
    """
    Click option to bypass prompts with a yes or no selection.
    """
    function = click.option(
        "--yes/--no",
        "-y/-n",
        help='Skip user prompts with a "yes" or "no" selection',
        default=None,
        show_default=True,
    )(function)
    return function


def opt_human_readable(function):
    """
    Click option to toggle raw / human-readable formatting.
    """
    function = click.option(
        "--human-readable/--no-human-readable",
        "-H",
        help="Reformat fields to be human readable.",
        default=False,
        show_default=True,
    )(function)
    return function


def opt_long(function):
    """
    Click option specifying that long or more detailed output should be produced.
    """
    function = click.option(
        "-l",
        "--long",
        help="Longer, more detailed output",
        is_flag=True,
        default=False,
        show_default=True,
    )(function)
    return function


def opt_open_browser(function):
    """
    Click option for specifying whether or not opening a browser is permitted
    for the planet_auth package's click commands.
    """
    function = click.option(
        "--open-browser/--no-open-browser",
        help="Allow/Suppress the automatic opening of a browser window.",
        default=True,
        show_default=True,
    )(function)
    return function


def opt_show_qr_code(function):
    """
    Click option for specifying whether or not a QR code should be displayed.
    """
    function = click.option(
        "--show-qr-code/--no-show-qr-code",
        help="Control whether a QR code is displayed for the user.",
        default=False,
        show_default=True,
    )(function)
    return function


def opt_token(function):
    """
    Click option for specifying a token literal.
    """
    function = click.option(
        "--token",
        help="Token string.",
        type=str,
        # envvar=EnvironmentVariables.AUTH_TOKEN,
        show_envvar=False,
        show_default=False,
    )(function)
    return function


def opt_token_file(function):
    """
    Click option for specifying a token file location for the
    planet_auth package's click commands.
    """
    function = click.option(
        "--token-file",
        type=click.Path(exists=True, file_okay=True, readable=True, path_type=pathlib.Path),
        envvar=EnvironmentVariables.AUTH_TOKEN_FILE,
        help="File containing a token.",
        default=None,
        show_envvar=False,
        show_default=True,
    )(function)
    return function


def opt_issuer(required=False):
    def decorator(function):
        """
        Click option for specifying an OAuth token issuer for the
        planet_auth package's click commands.
        """
        function = click.option(
            "--issuer",
            type=str,
            envvar=EnvironmentVariables.AUTH_ISSUER,
            help="Token issuer.",
            default=None,
            show_envvar=False,
            show_default=False,
            required=required,
        )(function)
        return function

    return decorator


def opt_audience(required=False):
    def decorator(function):
        """
        Click option for specifying an OAuth token audience for the
        planet_auth package's click commands.
        """
        function = click.option(
            "--audience",
            multiple=True,
            type=str,
            envvar=EnvironmentVariables.AUTH_AUDIENCE,
            help="Token audiences.  Specify multiple options to set"
            " multiple audiences.  When set via environment variable, audiences"
            " should be white space delimited.",
            default=None,
            show_envvar=True,
            show_default=True,
            required=required,
        )(function)
        return function

    return decorator


def opt_refresh(function):
    """
    Click option specifying a refresh should be attempted if applicable.
    """
    function = click.option(
        "--refresh/--no-refresh",
        help="Automatically perform a credential refresh if required.",
        default=True,
        show_default=True,
    )(function)
    return function


def opt_scope(function):
    """
    Click option for specifying an OAuth token scope for the
    planet_auth package's click commands.
    """
    function = click.option(
        "--scope",
        multiple=True,
        type=str,
        envvar=EnvironmentVariables.AUTH_SCOPE,
        help="Token scope.  Specify multiple options to specify"
        " multiple scopes.  When set via environment variable, scopes"
        " should be white space delimited.  Default value is determined"
        " by the selected auth profile.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function


def opt_sops(function):
    """
    Click option specifying that SOPS should be used.
    """
    function = click.option(
        "--sops/--no-sops",
        help="Use sops when creating new files where applicable."
        " The environment must be configured for SOPS to work by default.",
        default=False,
        show_default=True,
    )(function)
    return function


def opt_extra(function):
    """
    Click option for specifying extra options.
    """
    function = click.option(
        "--extra",
        "-O",
        multiple=True,
        type=str,
        envvar=EnvironmentVariables.AUTH_EXTRA,
        help="Specify an extra option.  Specify multiple options to specify"
        " multiple extra options.  The format of an option is <key>=<value>."
        " When set via environment variable, values should be delimited by"
        " whitespace.",
        default=None,
        show_envvar=True,
        show_default=True,
    )(function)
    return function
