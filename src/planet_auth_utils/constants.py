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

from typing import Optional

from planet_auth_utils.builtins import Builtins


class classproperty(object):
    def __init__(self, method=None):
        self.fget = method

    def __get__(self, instance, cls=None):
        return self.fget(cls)


class EnvironmentVariables:
    """
    Environment Variables used in the planet_auth_utils packages
    """

    @staticmethod
    def _namespace_variable(undecorated_variable: Optional[str]):
        """
        Decorate the variable name with a namespace.
        This is done so that multiple applications may use
        the Planet auth library without conflicting.
        """

        namespace = Builtins.namespace()
        if namespace and undecorated_variable:
            return f"{namespace.upper()}_{undecorated_variable}"
        return undecorated_variable

    @classproperty
    def AUTH_API_KEY(cls):  # pylint: disable=no-self-argument
        """
        A literal Planet API key.
        """
        return cls._namespace_variable("PL_API_KEY")

    @classproperty
    def AUTH_CLIENT_ID(cls):  # pylint: disable=no-self-argument
        """
        Client ID for an OAuth service account
        """
        # traceback.print_stack(file=sys.stdout)
        return cls._namespace_variable("PL_AUTH_CLIENT_ID")

    @classproperty
    def AUTH_CLIENT_SECRET(cls):  # pylint: disable=no-self-argument
        """
        Client Secret for an OAuth service account
        """
        return cls._namespace_variable("PL_AUTH_CLIENT_SECRET")

    @classproperty
    def AUTH_EXTRA(cls):  # pylint: disable=no-self-argument
        """
        List of extra options. Values should be formatted as <key>=<value>.
        Multiple options should be whitespace delimited.
        """
        return cls._namespace_variable("PL_AUTH_EXTRA")

    @classproperty
    def AUTH_PROFILE(cls):  # pylint: disable=no-self-argument
        """
        Name of a profile to use for auth client configuration.
        """
        return cls._namespace_variable("PL_AUTH_PROFILE")

    @classproperty
    def AUTH_TOKEN(cls):  # pylint: disable=no-self-argument
        """
        Literal token string.
        """
        return cls._namespace_variable("PL_AUTH_TOKEN")

    @classproperty
    def AUTH_TOKEN_FILE(cls):  # pylint: disable=no-self-argument
        """
        File path to use for storing tokens.
        """
        return cls._namespace_variable("PL_AUTH_TOKEN_FILE")

    @classproperty
    def AUTH_ISSUER(cls):  # pylint: disable=no-self-argument
        """
        Issuer to use when requesting or validating OAuth tokens.
        """
        return cls._namespace_variable("PL_AUTH_ISSUER")

    @classproperty
    def AUTH_AUDIENCE(cls):  # pylint: disable=no-self-argument
        """
        Audience to use when requesting or validating OAuth tokens.
        """
        return cls._namespace_variable("PL_AUTH_AUDIENCE")

    @classproperty
    def AUTH_ORGANIZATION(cls):  # pylint: disable=no-self-argument
        """
        Organization to use when performing client authentication.
        Only used for some authentication mechanisms.
        """
        return cls._namespace_variable("PL_AUTH_ORGANIZATION")

    @classproperty
    def AUTH_PROJECT(cls):  # pylint: disable=no-self-argument
        """
        Project ID to use when performing authentication.
        Not all implementations understand this option.
        """
        return cls._namespace_variable("PL_AUTH_PROJECT")

    @classproperty
    def AUTH_PASSWORD(cls):  # pylint: disable=no-self-argument
        """
        Password to use when performing client authentication.
        Only used for some authentication mechanisms.
        """
        return cls._namespace_variable("PL_AUTH_PASSWORD")

    @classproperty
    def AUTH_SCOPE(cls):  # pylint: disable=no-self-argument
        """
        List of scopes to request when requesting OAuth tokens.
        Multiple scopes should be whitespace delimited.
        """
        return cls._namespace_variable("PL_AUTH_SCOPE")

    @classproperty
    def AUTH_USERNAME(cls):  # pylint: disable=no-self-argument
        """
        Username to use when performing client authentication.
        Only used for some authentication mechanisms.
        """
        return cls._namespace_variable("PL_AUTH_USERNAME")

    @classproperty
    def AUTH_LOGLEVEL(cls):  # pylint: disable=no-self-argument
        """
        Specify the log level.
        """
        return cls._namespace_variable("PL_LOGLEVEL")
