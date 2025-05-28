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

import os
import pytest
import unittest

from planet_auth_config_injection import AUTH_BUILTIN_PROVIDER
from planet_auth_utils.builtins import Builtins, BuiltinsException

from tests.test_planet_auth_utils.util import TestWithHomeDirProfiles
from tests.test_planet_auth_utils.unit.auth_utils.builtins_test_impl import BuiltinConfigurationProviderMockTestImpl


class TestBuiltInProfiles:
    def test_load_auth_client_config_blank(self):
        with pytest.raises(BuiltinsException):  # as be:
            Builtins.load_builtin_auth_client_config(None)
        with pytest.raises(BuiltinsException):  # as be:
            Builtins.load_builtin_auth_client_config("")

    def test_load_auth_client_config_custom_profile(self):
        with pytest.raises(BuiltinsException):  # as be:
            Builtins.load_builtin_auth_client_config("custom_non_builtin_profile")

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


class TestAuthClientContextInitHelpers(TestWithHomeDirProfiles, unittest.TestCase):
    def setUp(self):
        os.environ[AUTH_BUILTIN_PROVIDER] = (
            "tests.test_planet_auth_utils.unit.auth_utils.builtins_test_impl.BuiltinConfigurationProviderMockTestImpl"
        )
        Builtins._builtin = None  # Reset built-in state.
        self.setUp_testHomeDir()

    def test_deailas_profile(self):
        under_test_resolved = Builtins.dealias_builtin_profile(
            BuiltinConfigurationProviderMockTestImpl.BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_1
        )
        self.assertEqual(under_test_resolved, BuiltinConfigurationProviderMockTestImpl.BUILTIN_PROFILE_NAME_UTEST_USER)

    def test_nested_deailas_profile(self):
        under_test_resolved = Builtins.dealias_builtin_profile(
            BuiltinConfigurationProviderMockTestImpl.BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_2
        )
        self.assertEqual(under_test_resolved, BuiltinConfigurationProviderMockTestImpl.BUILTIN_PROFILE_NAME_UTEST_USER)

    def test_deailas_non_builtin(self):
        with pytest.raises(BuiltinsException):  # as be:
            Builtins.dealias_builtin_profile("some_user_defined_non_builtin_profile")
