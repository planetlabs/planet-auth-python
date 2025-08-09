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

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


# Unlike other environment variables, AUTH_BUILTIN_PROVIDER is not name-spaced.
# It is intended for libraries and applications to inject configuration by
# being set within the program.  It's not expected to be set by end-users.
AUTH_BUILTIN_PROVIDER = "PL_AUTH_BUILTIN_CONFIG_PROVIDER"
"""
Environment variable to specify a python module and class that implement the
BuiltinConfigurationProviderInterface abstract interface to provide the library
and utility commands with some built-in configurations.
"""

_NOOP_AUTH_CLIENT_CONFIG = {
    "client_type": "none",
}


class BuiltinConfigurationProviderInterface(ABC):
    """
    Interface to define built-in application configuration.
    This includes providing built-in auth client configuration
    profiles, pre-defined trust environments for server use,
    and namespacing for environment and global configuration
    variables.

    Built-in profile names are expected to be all lowercase.

    Built-in trust environments are expected to be all uppercase.
    """

    def namespace(self) -> str:
        """
        Application namespace. This will be used as a prefix in various
        contexts so that multiple applications may use the Planet auth
        libraries in the same environment without collisions.  Presently,
        this namespace is used as a prefix for environment variables, and
        as a prefix for config settings store to the user's `~/.planet.json`
        file.
        """
        return ""

    @abstractmethod
    def builtin_client_authclient_config_dicts(self) -> Dict[str, dict]:
        """
        Return a dictionary of built-in AuthClient configuration
        dictionaries, keyed by a unique profile name.
        The returned dictionary values should be suitable for
        creating a functional configuration using
        `planet_auth.AuthClientConfig.config_from_dict`
        """

    def builtin_client_profile_aliases(self) -> Dict[str, str]:
        """
        Return a dictionary profile aliases.  Aliases allow
        for a single built-in configuration to be referred to
        by multiple names.
        """
        return {}

    @abstractmethod
    def builtin_default_profile_by_client_type(self) -> Dict[str, str]:
        """
        Return a dictionary of client types to default profile names for each client type.
        """

    @abstractmethod
    def builtin_default_profile(self) -> str:
        """
        Return the built-in default fallback auth profile name of last resort.
        """

    def builtin_trust_environment_names(self) -> List[str]:
        """
        Return a list of the names of built-in trust environments.
        """
        _realms = self.builtin_trust_environments()
        if _realms:
            return list(_realms.keys())
        return []

    def builtin_trust_environments(self) -> Dict[str, Optional[List[dict]]]:
        """
        Return a dictionary of the trust environment configurations.
        Each item in the lists should be valid AuthClient config dictionary.

        This is primarily used for cases where planet_auth is used to validate
        tokens on the service side.  This is the flip side of most of the other
        BuiltinConfigurationProviderInterface methods which are geared towards
        helping clients obtain tokens.
        """
        return {
            # "PRODUCTION": [MY_REALM_PRODUCTION],
            # "STAGING": [MY_REALM_STAGING],
            "CUSTOM": None,
        }


class EmptyBuiltinProfileConstants(BuiltinConfigurationProviderInterface):
    BUILTIN_PROFILE_NAME_NONE = "none"

    NONE_AUTH_CLIENT_CONFIG = {
        "client_type": "none",
    }

    _builtin_profile_auth_client_configs = {
        BUILTIN_PROFILE_NAME_NONE: NONE_AUTH_CLIENT_CONFIG,
    }

    _builtin_profile_default_by_client_type = {
        "none": BUILTIN_PROFILE_NAME_NONE,
    }

    def builtin_client_authclient_config_dicts(self) -> Dict[str, dict]:
        return EmptyBuiltinProfileConstants._builtin_profile_auth_client_configs

    def builtin_default_profile_by_client_type(self) -> Dict[str, str]:
        return EmptyBuiltinProfileConstants._builtin_profile_default_by_client_type

    def builtin_default_profile(self) -> str:
        return EmptyBuiltinProfileConstants.BUILTIN_PROFILE_NAME_NONE
