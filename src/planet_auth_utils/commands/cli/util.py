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

import click
import functools
import json
import logging

from planet_auth.constants import AUTH_CONFIG_FILE_SOPS, AUTH_CONFIG_FILE_PLAIN

from planet_auth_utils.builtins import Builtins
from planet_auth_utils.profile import Profile
from .prompts import prompt_change_user_default_profile_if_different


logger = logging.getLogger(__name__)


def recast_exceptions_to_click(*exceptions, **params):  # pylint: disable=W0613
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


def _custom_json_class_dumper(obj):
    try:
        return obj.__json_pretty_dumps__()
    except Exception:
        return obj


def print_obj(obj):
    json_str = json.dumps(obj, indent=2, sort_keys=True, default=_custom_json_class_dumper)
    print(json_str)


def post_login_cmd_helper(override_auth_context, current_auth_context, use_sops):
    # If someone performed a login with a non-default profile, it's
    # reasonable to ask if they intend to change their defaults
    prompt_change_user_default_profile_if_different(candidate_profile_name=override_auth_context.profile_name())

    # If the client config was created ad-hoc, offer to save it.  If the
    # config was created ad-hoc, the factory does not associate it with
    # a file to support factory use in a context where in memory
    # operations are desired.
    if (override_auth_context.profile_name() != current_auth_context.profile_name()) and (
        not Builtins.is_builtin_profile(override_auth_context.profile_name())
    ):
        if use_sops:
            new_profile_config_file_path = Profile.get_profile_file_path(
                profile=override_auth_context.profile_name(), filename=AUTH_CONFIG_FILE_SOPS
            )
        else:
            new_profile_config_file_path = Profile.get_profile_file_path(
                profile=override_auth_context.profile_name(), filename=AUTH_CONFIG_FILE_PLAIN
            )

        if not new_profile_config_file_path.exists():
            override_auth_context.auth_client().config().set_path(new_profile_config_file_path)
            override_auth_context.auth_client().config().save()

    # TODO? Set ctx.obj["AUTH"] to override_auth_context?
    #       Only if they responded "yes" to changing the default?
    #       It doesn't really matter, since we expect the program to exit.
