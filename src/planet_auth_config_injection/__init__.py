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

"""
# The Planet Authentication Library Configration Injection Package: `planet_auth_config_injection`

This package provides interfaces and utilities for higher-level applications
to inject configuration into the Planet Authentication Library.

The Planet Auth Library provides configuration injection to improve the
end-user experience of tools built on top of the Planet Auth Library.
This allows built-in default client configurations to be provided.
Namespacing may also be configured to avoid collisions in the Auth Library's
use of environment variables.  Injected configration is primarily consumed
by initialization functionality in planet_auth_utils.PlanetAuthFactory
and the various planet_auth_utils provided `click` commands.

These concerns belong more to the final end-user application than to a
library that sits between the Planet Auth library and the end-user
application.  Such libraries themselves may be used by a variety of
applications in any number of deployment environments, making the
decision of what configuration to inject a difficult one.

Library writers may provide configuration injection to their developers,
but should be conscious of the fact that multiple libraries within an
application may depend on Planet Auth libraries.  Library writers are
advised to provide configuration injection as an option for their users,
and not silently force it into the loaded.

In order to inject configuration, the application writer must do two things:

1. They must write a class that implements the
   [planet_auth_config_injection.BuiltinConfigurationProviderInterface][]
   interface.
2. They must set the environment variable `PL_AUTH_BUILTIN_CONFIG_PROVIDER` to the
   fully qualified package, module, and class name of their implementation
   _before_ any import of the `planet_auth` or `planet_auth_utils` packages.
"""

from .builtins_provider import (
    AUTH_BUILTIN_PROVIDER,
    BuiltinConfigurationProviderInterface,
    EmptyBuiltinProfileConstants,
)

__all__ = [
    "AUTH_BUILTIN_PROVIDER",
    "BuiltinConfigurationProviderInterface",
    "EmptyBuiltinProfileConstants",
]
