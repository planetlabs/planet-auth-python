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

import pytest

from planet_auth_utils.profile import ProfileException
from planet_auth_utils.builtins import Builtins, BuiltinsException

# FIXME: We are presuming a particular implementation of the built-in provider interface for these tests.
#        We should test with sometime self contained in this distribution package.


class TestBuiltInProfiles:
    def test_load_auth_client_config_blank(self):
        with pytest.raises(ProfileException):  # as pe:
            Builtins.load_auth_client_config(None)
        with pytest.raises(ProfileException):  # as pe:
            Builtins.load_auth_client_config("")

    def test_builtin_profile_auth_client_config_dict_blank(self):
        with pytest.raises(BuiltinsException):  # as be:
            Builtins.builtin_profile_auth_client_config_dict(None)
        with pytest.raises(BuiltinsException):  # as be:
            Builtins.builtin_profile_auth_client_config_dict("")

    def test_builtin_all_profile_dicts_are_valid(self):
        for builtin_name in Builtins.builtin_profile_names():
            builtin_dict = Builtins.builtin_profile_auth_client_config_dict(builtin_name)
            assert builtin_dict is not None

    # TODO
    # def test_load_empty_builtins(self):
    #     assert isinstance(Builtins._builtin, EmptyBuiltinProfileConstants)

    # TODO
    # def test_load_custom_builtins(self):
    #     assert isinstance(Builtins._builtin, SomeCustomProviderClass)
