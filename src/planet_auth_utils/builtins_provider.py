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

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


_NOOP_AUTH_CLIENT_CONFIG = {
    "client_type": "none",
}


class BuiltinConfigurationProviderInterface(ABC):
    """
    Interface to define what profiles are built-in.

    What auth configuration profiles are built-in is
    completely pluggable for users of the planet_auth and
    planet_auth_utils packages.  This is to support reuse
    in different deployments, or even support reuse by a
    different software stack all together.

    To inject built-in that override the coded in defaults,
    set the environment variable PL_AUTH_BUILTIN_CONFIG_PROVIDER
    to the module.classname of a class that implements this interface.

    Built-in profile names are expected to be all lowercase.

    Built-in trust environments are expected to be all uppercase.
    """

    @abstractmethod
    def builtin_client_authclient_config_dicts(self) -> Dict[str, dict]:
        """
        Return a dictionary of built-in AuthClient configuration
        dictionaries, keyed by a unique profile name.
        The returned dictionary values should be suitable for
        creating a functional configuration using
        `planet_auth.AuthClientConfig.config_from_dict`
        """

    @abstractmethod
    def builtin_client_profile_aliases(self) -> Dict[str, str]:
        """
        Return a dictionary profile aliases.  Aliases allow
        for a single built-in configuration to be referred to
        by multiple names.
        """

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

    @abstractmethod
    def builtin_trust_environment_names(self) -> List[str]:
        """
        Return a list of the names of built-in trust environments.
        """

    @abstractmethod
    def builtin_trust_environments(self) -> Dict[str, Optional[List[dict]]]:
        """
        Return a dictionary of the trust environment configurations.
        Each item in the lists should be valid AuthClient config dictionary.
        """


class EmptyBuiltinProfileConstants(BuiltinConfigurationProviderInterface):
    # TODO: add "None" type to this implementation.
    def builtin_client_authclient_config_dicts(self) -> Dict[str, dict]:
        return {}

    def builtin_client_profile_aliases(self) -> Dict[str, str]:
        return {}

    def builtin_default_profile_by_client_type(self):
        return {}

    def builtin_default_profile(self) -> str:
        return "__undefined__"

    def builtin_trust_environment_names(self) -> List[str]:
        return []

    def builtin_trust_environments(self) -> Dict[str, Optional[List[dict]]]:
        return {}
