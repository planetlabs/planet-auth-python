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

"""
# The Planet Authentication Utilities Package: `planet_auth_utils`

This utility package provides higher leven and convenience functions for
using the [planet_auth][] package.

The core functionality provided by this package includes:

- [planet_auth_utils.PlanetAuthFactory][] - Factory methods making it easier for application developers to initialize
    a coherent working set of [planet_auth] objects.
- `plauth` - The `plauth` command line utility is implemented in this package. It may be used
    as a stand-alone utility, or it may be embedded into other [click](https://click.palletsprojects.com/en/stable/) applications.
- [planet_auth_utils.Builtins][] - Built-in profile interface. Applications built on top of the
    _Planet Auth Library_ may use configuration injection provide built-in configurations
    suitable for the operating environment of the application.

"""

from .commands.cli.main import (
    cmd_plauth_embedded,
    cmd_plauth_login,
    cmd_plauth_reset,
    cmd_plauth_version,
)
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
    opt_qr_code,
    opt_refresh,
    opt_scope,
    opt_sops,
    opt_token,
    opt_token_file,
    opt_username,
    opt_yes_no,
)
from .commands.cli.util import recast_exceptions_to_click, monkeypatch_hide_click_cmd_options
from planet_auth_utils.constants import EnvironmentVariables
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.profile import Profile
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfig

__all__ = [
    "cmd_plauth_embedded",
    "cmd_plauth_login",
    "cmd_plauth_reset",
    "cmd_plauth_version",
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
    "opt_qr_code",
    "opt_refresh",
    "opt_scope",
    "opt_sops",
    "opt_token",
    "opt_token_file",
    "opt_username",
    "opt_yes_no",
    #
    "recast_exceptions_to_click",
    "monkeypatch_hide_click_cmd_options",
    #
    "Builtins",
    "EnvironmentVariables",
    "PlanetAuthFactory",
    "Profile",
    "PlanetAuthUserConfig",
]
