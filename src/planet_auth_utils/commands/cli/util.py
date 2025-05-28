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

import click
import functools
import json
from typing import List, Optional

import planet_auth
from planet_auth.constants import AUTH_CONFIG_FILE_SOPS, AUTH_CONFIG_FILE_PLAIN
from planet_auth.util import custom_json_class_dumper

from planet_auth_utils.builtins import Builtins
from planet_auth_utils.profile import Profile
from .prompts import prompt_and_change_user_default_profile_if_different


def monkeypatch_hide_click_cmd_options(cmd, hide_options: List[str]):
    """
    Monkey patch a click command to hide the specified command options.
    Useful when reusing click commands in contexts where you do not
    wish to expose all the options.
    """
    for hide_option in hide_options:
        for param in cmd.params:
            if param.name == hide_option:
                param.hidden = True
                break


def recast_exceptions_to_click(*exceptions, **params):  # pylint: disable=W0613
    """
    Decorator to catch exceptions and raise them as ClickExceptions.
    Useful to apply to `click` commands to supress stack traces that
    might be otherwise exposed to the end-user.
    """
    if not exceptions:
        exceptions = (Exception,)
    # params.get('some_arg', 'default')

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                raise click.ClickException(str(e))

        return wrapper

    return decorator


def print_obj(obj):
    json_str = json.dumps(obj, indent=2, sort_keys=True, default=custom_json_class_dumper)
    print(json_str)


def post_login_cmd_helper(
    override_auth_context: planet_auth.Auth, use_sops, prompt_pre_selection: Optional[bool] = None
):
    override_profile_name = override_auth_context.profile_name()
    if not override_profile_name:
        # Can't save to a profile if there is none.  We don't really expect this in the cases
        # where this is used for the CLI, but this keeps linters happy.
        return

    # If someone performed a login with a non-default profile, it's
    # reasonable to ask if they intend to change their defaults.
    prompt_and_change_user_default_profile_if_different(
        candidate_profile_name=override_profile_name, change_default_selection=prompt_pre_selection
    )

    # If the config was created ad-hoc by the factory, the factory does
    # not associate it with a file to support factory use in a context
    # where in-memory operations are desired.  This util function is for
    # helping CLI commands, we can be more opinionated about what is to
    # be done.

    # Don't clobber built-in profiles.
    if not Builtins.is_builtin_profile(override_profile_name):
        if use_sops:
            new_profile_config_file_path = Profile.get_profile_file_path(
                profile=override_profile_name, filename=AUTH_CONFIG_FILE_SOPS
            )
        else:
            new_profile_config_file_path = Profile.get_profile_file_path(
                profile=override_profile_name, filename=AUTH_CONFIG_FILE_PLAIN
            )

        # TODO? should we update if it exists with any command line options?
        #       The way things are currently structured, options added to the
        #       login command (like --scope) are not pushed down into the profile,
        #       but considered runtime overrides.
        if not new_profile_config_file_path.exists():
            override_auth_context.auth_client().config().set_path(new_profile_config_file_path)
            # No need to specify provider. The CLI is only concerned with the
            # default file based storage provider for now.
            # override_auth_context.auth_client().config().set_storage_provider()
            override_auth_context.auth_client().config().save()

    # TODO? Set ctx.obj["AUTH"] to override_auth_context?
    #       Only if they responded "yes" to changing the default?
    #       It doesn't really matter, since we expect the program to exit.
