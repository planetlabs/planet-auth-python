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

import importlib.resources
import os
import pathlib
import tempfile

from planet_auth_utils.profile import Profile


def tdata_resource_file_path(resource_file: str):
    file_path = importlib.resources.files("tests.test_planet_auth_utils").joinpath("data/" + resource_file)
    return file_path


class TestWithHomeDirProfiles:
    def setUp_testHomeDir(self):
        # pylint: disable=W0201
        self.test_home_dir = tempfile.TemporaryDirectory()
        self.test_home_dir_path = pathlib.Path(self.test_home_dir.name)
        self.old_home = os.environ.get("HOME")

        self.planet_dir_path = self.test_home_dir_path.joinpath(".planet")
        self.planet_dir_path.mkdir()

        os.environ["HOME"] = self.test_home_dir.name

    def tearDown_testHomeDir(self):
        if self.old_home:
            os.environ["HOME"] = self.old_home
        else:
            os.environ.pop("HOME")

    def mkProfileDir(self, profile_name) -> pathlib.Path:
        # Mimic the behavior of the default storage provider
        new_profile_dir_path = pathlib.Path.home() / Profile.get_profile_dir_path(profile_name)
        # new_profile_dir_path = Profile.get_profile_dir_path(profile_name)
        new_profile_dir_path.mkdir()
        return new_profile_dir_path
