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

import pathlib
from typing import List, Union

import planet_auth.logging.auth_logger
from planet_auth.auth_exception import AuthException
from planet_auth.auth_client import AuthClientConfig
from planet_auth.constants import (
    AUTH_CONFIG_FILE_SOPS,
    AUTH_CONFIG_FILE_PLAIN,
    PROFILE_DIR,
)
from planet_auth.storage_utils import ObjectStorageProvider


auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class ProfileException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class Profile:
    """
    Tools for managing configuration within a profile directory on disk.
    """

    @staticmethod
    def profile_root() -> pathlib.Path:
        """
        Root storage directory used for profile data.
        """
        # return pathlib.Path.home().joinpath(PROFILE_DIR)
        # We used to assume file storage.  We now support pluggable storage implementation.
        # We let the storage provider determine the real path (if there is one) and in this
        # Profile class we now (mostly) deal in the abstract idea of the path as an object
        # identifier that may or may not be file system based, depending on the storage
        # provider in use.
        return pathlib.Path(PROFILE_DIR)

    @staticmethod
    def get_profile_dir_path(profile: str) -> pathlib.Path:
        return Profile.profile_root().joinpath(profile.lower())

    @staticmethod
    def get_profile_file_path(
        filename: str, profile: str, override_path: Union[str, pathlib.PurePath, None] = None
    ) -> pathlib.Path:
        """
        Given a profile name and a file name, construct a file path for
        the file under the profile directory.  If an override is given,
        it will always be chosen.
        """
        if override_path:
            return pathlib.Path(override_path)

        if not profile or profile == "":
            raise ProfileException(message="profile must be set")

        return Profile.get_profile_dir_path(profile).joinpath(filename)

    @staticmethod
    def get_profile_file_path_with_priority(
        filenames: List[str],
        profile: str,
        override_path: Union[str, pathlib.PurePath, None] = None,
        # storage_provider: Optional[ObjectStorageProvider] = None,  # not yet supported here.
    ) -> pathlib.Path:
        """
        Given a list of candidate filenames, choose the first that that
        exists. If none exist, the last one will be used regardless of whether the
        file exists or not.  If the application needs the first rather than the
        last entry to be the fallback value, it should repeat that value and the
        end of the list.
        """
        if override_path:
            return pathlib.Path(override_path)

        last_candidate_path = None
        for candidate_filename in filenames:
            candidate_path = Profile.get_profile_file_path(
                filename=candidate_filename, profile=profile, override_path=None
            )
            last_candidate_path = candidate_path
            # TODO: custom storage providers not yet supported in this path
            _storage_provider = ObjectStorageProvider._default_storage_provider()
            if _storage_provider.obj_exists(candidate_path):
                return candidate_path

        return last_candidate_path  # type: ignore

    @staticmethod
    def load_auth_client_config(
        profile: str,
        # storage_provider: Optional[ObjectStorageProvider] = None,  # not yet supported here.
    ) -> AuthClientConfig:
        auth_config_path = Profile.get_profile_file_path_with_priority(
            filenames=[AUTH_CONFIG_FILE_SOPS, AUTH_CONFIG_FILE_PLAIN],
            profile=profile,
        )
        # TODO: custom storage providers not yet supported in this path
        _storage_provider = ObjectStorageProvider._default_storage_provider()
        if _storage_provider.obj_exists(auth_config_path):
            auth_logger.debug(msg='Using auth client configuration from "{}"'.format(str(auth_config_path)))
            client_config = AuthClientConfig.from_file(file_path=auth_config_path, storage_provider=_storage_provider)
        else:
            raise FileNotFoundError('Auth configuration file "{}" not found.'.format(str(auth_config_path)))

        return client_config

    @staticmethod
    def list_on_disk_profiles() -> List[str]:
        # Any directory in ~/.planet is only a potential profile. We only
        # consider it an actual profile if a client config file can be found.
        # Whether or not a profile is valid is not considered.

        # TODO: This assumes the default storage provider default behavior, since
        #   The placement under is now set by the storage provider, and not the Profile class.
        profile_abs_dir = pathlib.Path.home() / Profile.profile_root()
        if not profile_abs_dir.is_dir():
            return []
        candidate_profile_names = [x.name for x in profile_abs_dir.iterdir() if x.is_dir()]
        profile_names = []
        for candidate_profile_name in candidate_profile_names:
            config_file = Profile.get_profile_file_path_with_priority(
                profile=candidate_profile_name,
                filenames=[AUTH_CONFIG_FILE_SOPS, AUTH_CONFIG_FILE_PLAIN],
                override_path=None,
            )
            # TODO: custom storage providers not yet supported in this path
            _storage_provider = ObjectStorageProvider._default_storage_provider()
            if _storage_provider.obj_exists(config_file):
                profile_names.append(candidate_profile_name)

        profile_names.sort()
        return profile_names
