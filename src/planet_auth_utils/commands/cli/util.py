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
from click.core import ParameterSource
from typing import Callable, Dict, List, Optional

import planet_auth.logging.auth_logger
import planet_auth
from planet_auth import ObjectStorageProvider
from planet_auth.constants import AUTH_CONFIG_FILE_SOPS, AUTH_CONFIG_FILE_PLAIN
from planet_auth.storage_utils import _SOPSAwareFilesystemObjectStorageProvider
from planet_auth.util import custom_json_class_dumper

from planet_auth_utils.builtins import Builtins
from planet_auth_utils.plauth_factory import PlanetAuthFactory
from planet_auth_utils.profile import Profile
from .prompts import prompt_and_change_user_default_profile_if_different

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()

_AUTH_CONTEXT_OPTIONS = ("auth_profile", "auth_client_id", "auth_client_secret", "auth_api_key")
_SECRET_AUTH_CONTEXT_OPTIONS = {"auth_client_secret", "auth_api_key"}


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


def _describe_auth_option(name: str, value: Optional[str]) -> str:
    flag = "--" + name.replace("_", "-")
    if name in _SECRET_AUTH_CONTEXT_OPTIONS:
        return flag
    return f'{flag} "{value}"'


def login_auth_context(ctx: click.Context) -> planet_auth.Auth:
    """
    Resolve the auth context for a login command.  Auth options given on the
    command line to the login command are combined with the auth options
    given to its parent commands, and take priority over them.  Without such
    options, the auth context created by the root command is used.
    """
    login_options = {
        name: ctx.params[name]
        for name in _AUTH_CONTEXT_OPTIONS
        if ctx.params.get(name) is not None and ctx.get_parameter_source(name) == ParameterSource.COMMANDLINE
    }
    root_auth_context = (ctx.obj or {}).get("AUTH")
    if not login_options and root_auth_context is not None:
        return root_auth_context

    options: Dict[str, Optional[str]] = {}
    option_sources: Dict[str, Optional[ParameterSource]] = {}
    parent = ctx.parent
    while parent is not None:
        for name in _AUTH_CONTEXT_OPTIONS:
            if options.get(name) is None and parent.params.get(name) is not None:
                options[name] = parent.params[name]
                option_sources[name] = parent.get_parameter_source(name)
        parent = parent.parent

    for name, value in login_options.items():
        if options.get(name) is None or options[name] == value:
            continue
        msg = (
            f"{_describe_auth_option(name, value)} given to the {ctx.info_name} command overrides"
            f" {_describe_auth_option(name, options[name])} given to the parent command."
        )
        if option_sources.get(name) == ParameterSource.COMMANDLINE:
            auth_logger.warning(msg=msg)
        else:
            auth_logger.info(msg=msg)
    options.update(login_options)

    auth_context = PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=options.get("auth_profile"),
        auth_client_id_opt=options.get("auth_client_id"),
        auth_client_secret_opt=options.get("auth_client_secret"),
        auth_api_key_opt=options.get("auth_api_key"),
    )

    if root_auth_context is not None and root_auth_context.profile_name() != auth_context.profile_name():
        auth_logger.info(
            msg=f'The {ctx.info_name} command is using auth profile "{auth_context.profile_name()}"'
            f' in place of auth profile "{root_auth_context.profile_name()}" selected by the parent command.'
        )
    return auth_context


def login_extra_params(extra: Optional[List[str]], project: Optional[str], organization: Optional[str]) -> dict:
    login_extra = {}
    for extra_opt in extra or []:
        if "=" not in extra_opt:
            raise click.BadParameter(f'"{extra_opt}" is not in the form <key>=<value>.', param_hint="--extra")
        key, value = extra_opt.split("=", 1)
        login_extra[key] = value
    if project:
        # Planet Labs OAuth extension to request a token for a particular project
        login_extra["project_id"] = project
    if organization:
        # Used by Auth0's OAuth implementation to support their concept of selecting
        # a particular organization at login when the user belongs to more than one.
        login_extra["organization"] = organization
    return login_extra


def login_cmd_helper(
    ctx: click.Context,
    scope,
    audience,
    open_browser,
    show_qr_code,
    organization,
    project,
    extra,
    username,
    password,
    auth_client_id,
    auth_client_secret,
    sops,
    yes,
    check_auth_context: Optional[Callable[[planet_auth.Auth], None]] = None,
):
    """
    Common implementation of the login commands.
    """
    login_extra = login_extra_params(extra=extra, project=project, organization=organization)
    auth_context = login_auth_context(ctx)
    if check_auth_context:
        check_auth_context(auth_context)

    print(f"Logging in with authentication profile {auth_context.profile_name()}...")
    auth_context.login(
        requested_scopes=scope,
        requested_audiences=audience,
        allow_open_browser=open_browser,
        allow_tty_prompt=True,
        display_qr_code=show_qr_code,
        username=username,
        password=password,
        client_id=auth_client_id,
        client_secret=auth_client_secret,
        extra=login_extra,
    )
    print("Login succeeded.")  # Errors should throw.

    post_login_cmd_helper(override_auth_context=auth_context, use_sops_opt=sops, prompt_pre_selection=yes)


def post_login_cmd_helper(
    override_auth_context: planet_auth.Auth, use_sops_opt, prompt_pre_selection: Optional[bool] = None
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

    # If the profile was read from sops, selected sops even if wasn't an
    # explict command line option.
    use_sops = use_sops_opt
    if not use_sops:
        # Here in the CLI we can assume that the default storage provider
        # _SOPSAwareFilesystemObjectStorageProvider is being used.  Unlike general
        # library use, we do not support caller provided custom storage providers
        # in the CLI tools at this time.
        _config_data = override_auth_context.auth_client().config().data() or {}
        if (
            _config_data.get(_SOPSAwareFilesystemObjectStorageProvider._STORAGE_TYPE_KEY)
            == _SOPSAwareFilesystemObjectStorageProvider._StorageType.SOPS.value
        ):
            auth_logger.debug(msg="Implicitly selecting SOPS based on data originating from SOPS protected storage.")
            use_sops = True

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
        if not ObjectStorageProvider._default_storage_provider().obj_exists(new_profile_config_file_path):
            override_auth_context.auth_client().config().set_path(new_profile_config_file_path)
            # No need to specify provider. The CLI is only concerned with the
            # default file based storage provider for now.
            # override_auth_context.auth_client().config().set_storage_provider()
            override_auth_context.auth_client().config().save()

    # TODO? Set ctx.obj["AUTH"] to override_auth_context?
    #       Only if they responded "yes" to changing the default?
    #       It doesn't really matter, since we expect the program to exit.
