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

# TODO: We are not entirely consistent.
#       We use prompt_toolkit for major prompts
#       and click or simple code for others.

import click
from typing import Optional

# from prompt_toolkit.shortcuts import input_dialog, radiolist_dialog, yes_no_dialog

# from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfigEnhanced
from planet_auth_utils.constants import EnvironmentVariables


def prompt_and_change_user_default_profile_if_different(
    candidate_profile_name: str, change_default_selection: Optional[bool] = None
):
    config_file = PlanetAuthUserConfigEnhanced()
    try:
        saved_profile_name = config_file.lazy_get(EnvironmentVariables.AUTH_PROFILE)
    except FileNotFoundError:
        saved_profile_name = None  # config_file.effective_conf_value(EnvironmentVariables.AUTH_PROFILE, fallback_value=Builtins.builtin_default_profile_name())

    if not saved_profile_name:
        # Always write a preference if none is saved.
        # Since CLI options and env vars are higher priority than this file,
        # it should not cause surprises.
        do_change_default = True
    elif change_default_selection is not None:
        do_change_default = change_default_selection
    else:
        do_change_default = False
        if saved_profile_name != candidate_profile_name:
            # do_change_default = yes_no_dialog(
            #     title=f'Change user default {EnvironmentVariables.AUTH_PROFILE} saved in {config_file.path()}?',
            #     text=f'Current value and user default differ.\nDo you want to change the user default {EnvironmentVariables.AUTH_PROFILE} from "{saved_profile_name}" to "{candidate_profile_name}"?',
            #     yes_text="Change",
            #     no_text="Keep",
            # ).run()
            do_change_default = click.confirm(
                text=f'\nCurrent value and user default differ.\nDo you want to change the user default {EnvironmentVariables.AUTH_PROFILE} from "{saved_profile_name}" to "{candidate_profile_name}"? ',
            )

    if do_change_default:
        config_file.update_data({EnvironmentVariables.AUTH_PROFILE: candidate_profile_name})
        config_file.save()

    return do_change_default
