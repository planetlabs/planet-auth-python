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

from .commands.cli.main import cmd_plauth_embedded, cmd_plauth_login
from .commands.cli.planet_legacy_auth_cmd import (
    cmd_pllegacy,
    cmd_pllegacy_login,
    cmd_pllegacy_print_api_key,
    cmd_pllegacy_print_access_token,
)
from .commands.cli.oauth_cmd import (
    cmd_oauth,
    cmd_oauth_login,
    cmd_oauth_refresh,
    cmd_oauth_validate_access_token_local,
    cmd_oauth_validate_access_token_remote,
    cmd_oauth_validate_id_token_local,
    cmd_oauth_validate_id_token_remote,
    cmd_oauth_validate_refresh_token_remote,
    cmd_oauth_revoke_access_token,
    cmd_oauth_revoke_refresh_token,
    cmd_oauth_userinfo,
    cmd_oauth_discovery,
    cmd_oauth_list_scopes,
    cmd_oauth_print_access_token,
)
from .commands.cli.profile_cmd import (
    cmd_profile,
    cmd_profile_list,
    cmd_profile_create,
    # cmd_profile_edit,
    cmd_profile_copy,
    cmd_profile_set,
    cmd_profile_show,
)
from .commands.cli.jwt_cmd import (
    cmd_jwt,
    cmd_jwt_decode,
    cmd_jwt_validate_oauth,
)
from .commands.cli.options import (
    opt_api_key,
    opt_audience,
    opt_client_id,
    opt_client_secret,
    opt_extra,
    opt_human_readable,
    opt_issuer,
    opt_loglevel,
    opt_long,
    opt_open_browser,
    opt_organization,
    opt_password,
    opt_profile,
    opt_project,
    opt_refresh,
    opt_scope,
    opt_show_qr_code,
    opt_sops,
    opt_token,
    opt_token_file,
    opt_username,
    opt_yes_no,
)
from .commands.cli.util import recast_exceptions_to_click
from planet_auth_utils.constants import EnvironmentVariables
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.profile import Profile
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfig

__all__ = [
    "cmd_plauth_embedded",
    "cmd_plauth_login",
    "cmd_jwt",
    "cmd_jwt_decode",
    "cmd_jwt_validate_oauth",
    "cmd_oauth",
    "cmd_oauth_login",
    "cmd_oauth_refresh",
    "cmd_oauth_validate_access_token_local",
    "cmd_oauth_validate_access_token_remote",
    "cmd_oauth_validate_id_token_local",
    "cmd_oauth_validate_id_token_remote",
    "cmd_oauth_validate_refresh_token_remote",
    "cmd_oauth_revoke_access_token",
    "cmd_oauth_revoke_refresh_token",
    "cmd_oauth_userinfo",
    "cmd_oauth_discovery",
    "cmd_oauth_list_scopes",
    "cmd_oauth_print_access_token",
    "cmd_pllegacy",
    "cmd_pllegacy_login",
    "cmd_pllegacy_print_api_key",
    "cmd_pllegacy_print_access_token",
    "cmd_profile",
    "cmd_profile_list",
    "cmd_profile_create",
    # "cmd_profile_edit",
    "cmd_profile_copy",
    "cmd_profile_set",
    "cmd_profile_show",
    "opt_api_key",
    "opt_audience",
    "opt_client_id",
    "opt_client_secret",
    "opt_extra",
    "opt_human_readable",
    "opt_issuer",
    "opt_loglevel",
    "opt_long",
    "opt_open_browser",
    "opt_organization",
    "opt_password",
    "opt_profile",
    "opt_project",
    "opt_refresh",
    "opt_scope",
    "opt_show_qr_code",
    "opt_sops",
    "opt_token",
    "opt_token_file",
    "opt_username",
    "opt_yes_no",
    "recast_exceptions_to_click",
    #
    "Builtins",
    "EnvironmentVariables",
    "PlanetAuthFactory",
    "Profile",
    "PlanetAuthUserConfig",
]
