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

"""
Planet Authentication and Authorization CLI Utilities.

These utilities are thin wrappers for functionality implemented
by the underlying auth libraries.

"""

from .commands.cli.main import embedded_plauth_cmd_group
from .commands.cli.options import (
    opt_auth_api_key,
    opt_auth_client_id,
    opt_auth_client_secret,
    opt_auth_profile,
    opt_show_qr_code,
    opt_token_file,
)
from .commands.cli.util import recast_exceptions_to_click
from planet_auth_utils.constants import EnvironmentVariables
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.profile import Profile

__all__ = [
    # embedded_plauth_cmd_group.__name__,
    "embedded_plauth_cmd_group",
    opt_auth_api_key.__name__,
    opt_auth_client_id.__name__,
    opt_auth_client_secret.__name__,
    opt_auth_profile.__name__,
    opt_show_qr_code.__name__,
    opt_token_file.__name__,
    recast_exceptions_to_click.__name__,
    EnvironmentVariables.__name__,
    PlanetAuthFactory.__name__,
    Builtins.__name__,
    Profile.__name__,
]
