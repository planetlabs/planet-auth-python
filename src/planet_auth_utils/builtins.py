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
import importlib
import logging
import os
from typing import List, Optional

from planet_auth import AuthClientConfig, AuthException
from planet_auth_utils.profile import Profile
from planet_auth_utils.constants import EnvironmentVariables
from .builtins_provider import BuiltinConfigurationProviderInterface, EmptyBuiltinProfileConstants

logger = logging.getLogger(__name__)


class BuiltinsException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


def _load_builtins_worker(builtin_provider_fq_class_name, log_warning=False):
    if not builtin_provider_fq_class_name:
        return

    module_name, _, class_name = builtin_provider_fq_class_name.rpartition(".")
    if module_name and class_name:
        try:
            builtin_provider_module = importlib.import_module(module_name)  # nosemgrep - WARNING - See below
            if class_name not in builtin_provider_module.__dict__:
                logger.warning(
                    "Error loading built-in provider. Module %s does not contain class %s.",
                    module_name,
                    class_name,
                )
            else:
                provider_instance = builtin_provider_module.__dict__[class_name]()
                return provider_instance
        except ImportError as ie:
            if log_warning:
                logger.warning(
                    "Error loading built-in provider %s. Error: %s.",
                    builtin_provider_fq_class_name,
                    ie.msg,
                )
    else:
        logger.warning(
            "'%s' could not be parsed for module and class name while loading built-in provider.",
            builtin_provider_fq_class_name,
        )
    return None


def _load_builtins() -> BuiltinConfigurationProviderInterface:
    # Highest priority : injected
    # WARNING: This environment variable is highly sensitive.
    #     Undermining it can undermine client or service security.
    #     It is a convenience for seamless developer experience, but maybe
    #     we should not be so eager to please.
    builtin_provider = _load_builtins_worker(os.getenv(EnvironmentVariables.AUTH_BUILTIN_PROVIDER))
    if builtin_provider:
        return builtin_provider

    # Next priority : Well known implementations (Planet engineering internal)
    builtin_provider = _load_builtins_worker("planet_auth_config.BuiltinConfigurationProvider")
    if builtin_provider:
        return builtin_provider

    # Fallback : The empty provider
    return EmptyBuiltinProfileConstants()


class Builtins:
    _builtin: BuiltinConfigurationProviderInterface = None  # type: ignore

    @staticmethod
    def _load_builtin_jit():
        if not Builtins._builtin:
            Builtins._builtin = _load_builtins()

    @staticmethod
    def is_builtin_profile(profile: str) -> bool:
        Builtins._load_builtin_jit()
        if profile:
            _profile = profile.lower()
        else:
            _profile = None

        return (
            _profile in Builtins._builtin.builtin_client_authclient_config_dicts()
            or _profile in Builtins._builtin.builtin_client_profile_aliases()
        )

    @staticmethod
    def is_builtin_profile_alias(profile: str) -> bool:
        Builtins._load_builtin_jit()
        if profile:
            _profile = profile.lower()
        else:
            _profile = None
        return _profile in Builtins._builtin.builtin_client_profile_aliases()

    @staticmethod
    def dealias_builtin_profile(profile: str) -> Optional[str]:
        Builtins._load_builtin_jit()
        if Builtins.is_builtin_profile_alias(profile):
            return Builtins._builtin.builtin_client_profile_aliases().get(profile.lower())
        elif Builtins.is_builtin_profile(profile):
            return profile.lower()
        else:
            return None

    @staticmethod
    def builtin_profile_names() -> List[str]:
        """
        Return a list of all the built-in profile names.
        """
        Builtins._load_builtin_jit()
        return list(Builtins._builtin.builtin_client_authclient_config_dicts().keys()) + list(
            Builtins._builtin.builtin_client_profile_aliases().keys()
        )

    @staticmethod
    def builtin_profile_auth_client_config_dict(profile: str) -> dict:
        Builtins._load_builtin_jit()
        if not profile:
            raise BuiltinsException(message="profile must be set")

        if Builtins.is_builtin_profile(profile):
            _profile = Builtins.dealias_builtin_profile(profile)
            return Builtins._builtin.builtin_client_authclient_config_dicts().get(_profile)  # type: ignore
        else:
            raise BuiltinsException(message=f"profile {profile} is unknown.")

    # @staticmethod
    # def builtin_profile_auth_client_config(profile: str):
    #     return AuthClientConfig.from_dict(Builtins._builtin_profile_auth_client_configs.get(profile))

    @staticmethod
    def load_auth_client_config(profile: str) -> AuthClientConfig:
        Builtins._load_builtin_jit()
        if Builtins.is_builtin_profile(profile):
            logger.debug(
                'Using built-in "%s" auth client configuration (ignoring on disk config, if it exists)',
                profile.lower(),
            )
            client_config = AuthClientConfig.from_dict(Builtins.builtin_profile_auth_client_config_dict(profile))
        else:
            # TODO: does this belong in this class anymore? This is a vestige of when "Builtins" was "Profiles"
            client_config = Profile.load_client_config(profile)

        return client_config

    @staticmethod
    def builtin_default_profile_name(client_type: Optional[str] = None) -> str:
        Builtins._load_builtin_jit()
        if client_type in Builtins._builtin.builtin_default_profile_by_client_type():
            return Builtins._builtin.builtin_default_profile_by_client_type()[client_type]
        return Builtins._builtin.builtin_default_profile()

    @staticmethod
    def builtin_environment_names() -> List[str]:
        Builtins._load_builtin_jit()
        return Builtins._builtin.builtin_trust_environment_names()

    @staticmethod
    def builtin_environment(environment: str) -> Optional[List[dict]]:
        Builtins._load_builtin_jit()
        # TODO : distinguish between unknown, and known and set to None (e.g. CUSTOM)
        if environment in Builtins._builtin.builtin_trust_environments():
            _builtin_env = Builtins._builtin.builtin_trust_environments().get(environment.upper())
            return _builtin_env
        else:
            raise BuiltinsException(message=f"environment {environment.upper()} is unknown.")
