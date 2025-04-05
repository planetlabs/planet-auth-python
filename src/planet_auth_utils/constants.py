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


class EnvironmentVariables:
    """
    Environment Variables used in the planet_auth_utils packages
    """

    AUTH_API_KEY = "PL_API_KEY"
    """
    A literal Planet API key.
    """

    AUTH_CLIENT_ID = "PL_AUTH_CLIENT_ID"
    """
    Client ID for an OAuth service account
    """

    AUTH_CLIENT_SECRET = "PL_AUTH_CLIENT_SECRET"
    """
    Client Secret for an OAuth service account
    """

    AUTH_EXTRA = "PL_AUTH_EXTRA"
    """
    List of extra options.  Values should be formatted as <key>=<value>.
    Multiple options should be whitespace delimited.
    """

    AUTH_PROFILE = "PL_AUTH_PROFILE"
    """
    Name of a profile to use for auth client configuration.
    """

    AUTH_TOKEN = "PL_AUTH_TOKEN"
    """
    Literal token string.
    """

    AUTH_TOKEN_FILE = "PL_AUTH_TOKEN_FILE"
    """
    File path to use for storing tokens.
    """

    AUTH_ISSUER = "PL_AUTH_ISSUER"
    """
    Issuer to use when requesting or validating OAuth tokens.
    """

    AUTH_AUDIENCE = "PL_AUTH_AUDIENCE"
    """
    Audience to use when requesting or validating OAuth tokens.
    """

    AUTH_ORGANIZATION = "PL_AUTH_ORGANIZATION"
    """
    Organization to use when performing client authentication.
    Only used for some authentication mechanisms.
    """

    AUTH_PASSWORD = "PL_AUTH_PASSWORD"
    """
    Password to use when performing client authentication.
    Only used for some authentication mechanisms.
    """

    AUTH_SCOPE = "PL_AUTH_SCOPE"
    """
    List of scopes to request when requesting OAuth tokens.
    Multiple scopes should be whitespace delimited.
    """

    AUTH_USERNAME = "PL_AUTH_USERNAME"
    """
    Username to use when performing client authentication.
    Only used for some authentication mechanisms.
    """

    AUTH_LOGLEVEL = "PL_LOGLEVEL"
    """
    Specify the log level.
    """

    AUTH_BUILTIN_PROVIDER = "PL_AUTH_BUILTIN_CONFIG_PROVIDER"
    """
    Specify a python module and class that implement the BuiltinConfigurationProviderInterface abstract
    interface to provide the library and utility commands with some built-in configurations.
    """
