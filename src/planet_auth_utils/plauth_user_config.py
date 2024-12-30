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

import os
import pathlib
import logging
from typing import Optional

from planet_auth.util import FileBackedJsonObject
from planet_auth.constants import USER_CONFIG_FILE


logger = logging.getLogger(__name__)


class PlanetAuthUserConfig(FileBackedJsonObject):
    """
    Access a ~/.planet.json file to store preferences that are not
    part of a particular AuthClient configuration profile.
    """

    @staticmethod
    def default_user_config_file():
        # return Profile.profile_root().joinpath(USER_CONFIG_FILE)
        return pathlib.Path.home().joinpath(USER_CONFIG_FILE)

    def __init__(self, data: Optional[dict] = None, file_path: Optional[pathlib.Path] = None):
        if file_path is None:
            file_path = PlanetAuthUserConfig.default_user_config_file()
        super().__init__(data=data, file_path=file_path)


class PlanetAuthUserConfigEnhanced(PlanetAuthUserConfig):
    """
    Provide an enhanced view of the `~/.planet.json` configuration file,
    with utilities to consolidate the retrieval of configuration
    parameters user overrides, environment variables, the configuration file,
    or fallback internals defaults.
    """

    def effective_conf_value(
        self,
        config_key: str,
        override_value: Optional[str] = None,
        fallback_value: Optional[str] = None,
        env_var_name: Optional[str] = None,
        use_env: bool = True,
        use_configfile: bool = True,
    ):
        """
        Return the effective configuration value synthesized from a variety of sources,
        with the following priority applied:
            - Explicit values from the user are given the highest priority.
            - Values taken from environment variables are then considered.
            - Values taken from the user's configuration file are then next considered.
              The default user configuration file is `~/.planet.json`.
            - Built-in default values are considered last.
        Parameters:
            config_key:  The configuration key to look up.  By default, this will be used
                both for reading the user's configuration file, and used as the environment
                variable to search for.
            override_value: User provided override value.  If this value is supplied,
                it will be returned.
            fallback_value: A fallback default value to return if the config parameter
                cannot be found in the user's configuration file or the environment, and the
                user did not provide an explicit override value.
            env_var_name: Name of the environment variable to search for a value.
                If not provided, the `config_key` will also be used as the environment
                variable.
            use_env: Boolean controlling whether the environment should be considered.
                By default, the environment will be searched for configuration values,
                but this behavior can be surprised using this parameter.
            use_configfile: Boolean controlling whether the user configuration file should be considered.
                By default, the user configuration file will be searched for configuration values,
                but this behavior can be surprised using this parameter.
        """
        if override_value:
            return override_value

        if use_env:
            if env_var_name:
                _env_var = env_var_name
            else:
                _env_var = config_key
            if os.getenv(_env_var):
                return os.getenv(_env_var)

        if use_configfile:
            try:
                # It's the caller's job to decide when a reload is safe.
                # config_file_value = self.lazy_reload_get(config_key)
                config_file_value = self.lazy_get(config_key)
                if config_file_value:
                    return config_file_value
            except Exception as ex:
                logger.debug(f"{ex}")  # pylint: disable=W1203

        return fallback_value
