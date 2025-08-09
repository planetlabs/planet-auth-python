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
import shutil
import unittest

from planet_auth.auth_client import AuthClientException
from planet_auth.constants import AUTH_CONFIG_FILE_PLAIN
from planet_auth.static_api_key.auth_client import StaticApiKeyAuthClientConfig

from planet_auth_utils.profile import Profile, ProfileException
from tests.test_planet_auth_utils.util import tdata_resource_file_path, TestWithHomeDirProfiles


PROFILE1_NAME = "profile1_static_api_key"
PROFILE2_NAME = "profile2_invalid"
PROFILE3_NAME = "profile3_empty"


class ProfileTest(TestWithHomeDirProfiles, unittest.TestCase):
    def setUp(self):
        self.setUp_testHomeDir()

        self.profile1_dir_path = self.mkProfileDir(PROFILE1_NAME)
        shutil.copy(
            tdata_resource_file_path("auth_client_configs/utest/static_api_key.json"),
            self.profile1_dir_path.joinpath(AUTH_CONFIG_FILE_PLAIN),
        )

        self.profile2_dir_path = self.mkProfileDir(PROFILE2_NAME)
        shutil.copy(
            tdata_resource_file_path("auth_client_configs/utest/invalid_client_config.json"),
            self.profile2_dir_path.joinpath(AUTH_CONFIG_FILE_PLAIN),
        )

        self.profile3_dir_path = self.mkProfileDir(PROFILE3_NAME)

    def tearDown(self) -> None:
        self.tearDown_testHomeDir()

    def test_filepath_no_profile_no_override(self):
        with self.assertRaises(ProfileException):
            Profile.get_profile_file_path(filename="testfile.dat", profile=None, override_path=None)
        # Old behavior
        # self.assertIsInstance(under_test, pathlib.Path)
        # self.assertEqual(pathlib.Path.home().joinpath(".planet/default/testfile.dat"), under_test)

    def test_filepath_blank_profile_no_override(self):
        with self.assertRaises(ProfileException):
            Profile.get_profile_file_path(filename="testfile.dat", profile="", override_path=None)
        # Old behavior
        # self.assertIsInstance(under_test, pathlib.Path)
        # self.assertEqual(pathlib.Path.home().joinpath(".planet/default/testfile.dat"), under_test)

    def test_filepath_blank_profile_with_override(self):
        under_test = Profile.get_profile_file_path(filename="testfile.dat", profile="", override_path="/override")
        self.assertIsInstance(under_test, pathlib.Path)
        self.assertEqual(pathlib.Path("/override"), under_test)

    def test_filepath(self):
        under_test = Profile.get_profile_file_path(filename="testfile.dat", profile="test_profile", override_path=None)
        self.assertIsInstance(under_test, pathlib.Path)
        self.assertEqual(pathlib.Path(".planet/test_profile/testfile.dat"), under_test)

    def test_pathfile_override(self):
        under_test = Profile.get_profile_file_path(
            filename="testfile.dat", profile="test_profile", override_path="/override"
        )
        self.assertIsInstance(under_test, pathlib.Path)
        self.assertEqual(pathlib.Path("/override"), under_test)

    def test_priority_path_with_override(self):
        under_test = Profile.get_profile_file_path_with_priority(
            filenames=["does_not_exist_1", "does_not_exist_2"], profile="test_profile", override_path="/override"
        )
        self.assertEqual(pathlib.Path("/override"), under_test)

    def test_priority_path_fallback_behavior(self):
        under_test = Profile.get_profile_file_path_with_priority(
            filenames=["does_not_exist_1", "does_not_exist_2"], profile="test_profile", override_path=None
        )
        self.assertEqual(pathlib.Path(".planet/test_profile/does_not_exist_2"), under_test)

    def test_priority_path_first_choice_wins_if_exists(self):
        profile_dir = pathlib.Path.home().joinpath(".planet/test_profile")
        profile_dir.mkdir(parents=True, exist_ok=True)
        pathlib.Path.home().joinpath(".planet/test_profile/does_exist_1").touch()
        under_test = Profile.get_profile_file_path_with_priority(
            filenames=["does_exist_1", "does_not_exist_2"], profile="test_profile", override_path=None
        )
        self.assertEqual(pathlib.Path(".planet/test_profile/does_exist_1"), under_test)

    def test_load_client_none(self):
        with self.assertRaises(ProfileException):
            Profile.load_auth_client_config(profile=None)

    def test_load_client_custom_profile_ok(self):
        client_conf = Profile.load_auth_client_config(profile=PROFILE1_NAME)
        self.assertIsInstance(client_conf, StaticApiKeyAuthClientConfig)

    def test_load_client_custom_profile_invalid(self):
        with self.assertRaises(AuthClientException):
            Profile.load_auth_client_config(profile=PROFILE2_NAME)

    def test_load_client_custom_profile_does_not_exist(self):
        with self.assertRaises(FileNotFoundError):
            Profile.load_auth_client_config(profile="profile_does_not_exist")

    def test_list_profiles(self):
        profile_list = Profile.list_on_disk_profiles()
        self.assertEqual(profile_list, [PROFILE1_NAME, PROFILE2_NAME])
