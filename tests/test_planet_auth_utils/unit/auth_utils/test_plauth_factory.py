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
import shutil
import unittest

import planet_auth
import planet_auth.storage_utils
from planet_auth.constants import AUTH_CONFIG_FILE_PLAIN

from planet_auth_config_injection import AUTH_BUILTIN_PROVIDER
from planet_auth_utils.builtins import Builtins
from planet_auth_utils.constants import EnvironmentVariables
from planet_auth_utils.plauth_factory import PlanetAuthFactory, MissingArgumentException
from planet_auth_utils.plauth_user_config import PlanetAuthUserConfig
from planet_auth_utils.profile import Profile

from .builtins_test_impl import MockProductionEnv, MockStagingEnv

from tests.test_planet_auth_utils.util import tdata_resource_file_path, TestWithHomeDirProfiles

PROFILE1_NAME = "test_profile1"
PROFILE2_NAME = "test_profile2"
PROFILE3_NAME = "test_profile3"


class TestAuthClientContextInitHelpers(TestWithHomeDirProfiles, unittest.TestCase):
    def setUp(self):
        os.environ[AUTH_BUILTIN_PROVIDER] = (
            "tests.test_planet_auth_utils.unit.auth_utils.builtins_test_impl.BuiltinConfigurationProviderMockTestImpl"
        )
        Builtins._builtin = None  # Reset built-in state.
        self.setUp_testHomeDir()

        self.profile1_dir_path = self.mkProfileDir(PROFILE1_NAME)
        shutil.copy(
            tdata_resource_file_path("auth_client_configs/utest/static_api_key.json"),
            self.profile1_dir_path.joinpath(planet_auth.constants.AUTH_CONFIG_FILE_PLAIN),
        )

        self.profile2_dir_path = self.mkProfileDir(PROFILE2_NAME)
        shutil.copy(
            tdata_resource_file_path("auth_client_configs/utest/static_api_key.json"),
            self.profile2_dir_path.joinpath(planet_auth.constants.AUTH_CONFIG_FILE_PLAIN),
        )

        self.profile3_dir_path = self.mkProfileDir(PROFILE3_NAME)
        shutil.copy(
            tdata_resource_file_path("auth_client_configs/utest/static_api_key.json"),
            self.profile3_dir_path.joinpath(planet_auth.constants.AUTH_CONFIG_FILE_PLAIN),
        )

        self.under_test_storage_provider = planet_auth.storage_utils.ObjectStorageProvider._default_storage_provider()

    def tearDown(self) -> None:
        self.tearDown_testHomeDir()
        os.environ.pop(EnvironmentVariables.AUTH_PROFILE, None)
        os.environ.pop(EnvironmentVariables.AUTH_API_KEY, None)
        os.environ.pop(EnvironmentVariables.AUTH_CLIENT_ID, None)
        os.environ.pop(EnvironmentVariables.AUTH_CLIENT_SECRET, None)

    def write_test_conf_file(self, data):
        conf_file = PlanetAuthUserConfig(data=data)
        conf_file.save()

    def test_default_initialization(self):
        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(
            under_test.profile_name(), Builtins.dealias_builtin_profile(Builtins.builtin_default_profile_name())
        )
        # self.assertIsInstance(under_test.auth_client(), planet_auth.XXX)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_dot_planet_json_profile(self):
        self.write_test_conf_file(
            {
                EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), PROFILE3_NAME)
        # self.assertIsInstance(under_test.auth_client(), planet_auth.XXX)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_dot_planet_json_m2m(self):
        self.write_test_conf_file(
            {
                # EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME, # Higher priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), "utest-m2m-unit_test_conffile_client_id")
        self.assertEqual(
            under_test._auth_client._auth_client_config.lazy_get("client_id"), "unit_test_conffile_client_id"
        )
        self.assertEqual(
            under_test._auth_client._auth_client_config.lazy_get("client_secret"), "unit_test_conffile_client_secret"
        )
        self.assertIsInstance(under_test.auth_client(), planet_auth.ClientCredentialsClientSecretAuthClient)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_dot_planet_json_api_key(self):
        self.write_test_conf_file(
            {
                # EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME, # Higher priority
                # EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id", # Higher priority
                # EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret", # Higher priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",
                "key": "PLAK_conffile_API_key_backwards_compat",
            }
        )

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), "_PL_API_KEY")
        self.assertIsInstance(under_test.auth_client(), planet_auth.StaticApiKeyAuthClient)
        self.assertEqual(under_test._auth_client._auth_client_config.lazy_get("api_key"), "PLAK_conffile_API_key")
        self.assertIsNone(under_test.token_file_path())

    def test_init_from_dot_planet_json_api_key_backwards_compatibility(self):
        self.write_test_conf_file(
            {
                # We also accept the config key used by older versions of the SDK
                "key": "PLAK_conffile_API_key_backwards_compat",
            }
        )

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), "_PL_API_KEY")
        self.assertIsInstance(under_test.auth_client(), planet_auth.StaticApiKeyAuthClient)
        self.assertEqual(
            under_test._auth_client._auth_client_config.lazy_get("api_key"), "PLAK_conffile_API_key_backwards_compat"
        )
        self.assertIsNone(under_test.token_file_path())

    def test_init_from_env_profile(self):
        self.write_test_conf_file(
            {
                EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ[EnvironmentVariables.AUTH_PROFILE] = PROFILE1_NAME
        os.environ[EnvironmentVariables.AUTH_CLIENT_ID] = "unit_test_env_client_id"  # Lower priority
        os.environ[EnvironmentVariables.AUTH_CLIENT_SECRET] = "unit_test_env_client_secret"  # Lower priority
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"  # Lower priority

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), PROFILE1_NAME)
        # self.assertIsInstance(under_test.auth_client(), planet_auth.XXX)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_env_oauth_m2m(self):
        self.write_test_conf_file(
            {
                # EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Higher priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ.pop(EnvironmentVariables.AUTH_PROFILE, None)  # Higher priority
        os.environ[EnvironmentVariables.AUTH_CLIENT_ID] = "unit_test_env_client_id"
        os.environ[EnvironmentVariables.AUTH_CLIENT_SECRET] = "unit_test_env_client_secret"
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"  # Lower priority

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), "utest-m2m-unit_test_env_client_id")
        self.assertEqual(under_test._auth_client._auth_client_config.lazy_get("client_id"), "unit_test_env_client_id")
        self.assertEqual(
            under_test._auth_client._auth_client_config.lazy_get("client_secret"), "unit_test_env_client_secret"
        )
        self.assertIsInstance(under_test.auth_client(), planet_auth.ClientCredentialsClientSecretAuthClient)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_env_api_key(self):
        self.write_test_conf_file(
            {
                # EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Higher priority
                # EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Higher priority
                # EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Higher priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ.pop(EnvironmentVariables.AUTH_PROFILE, None)  # Higher priority
        os.environ.pop(EnvironmentVariables.AUTH_CLIENT_ID, None)  # Higher priority
        os.environ.pop(EnvironmentVariables.AUTH_CLIENT_SECRET, None)  # Higher priority
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"

        under_test = PlanetAuthFactory.initialize_auth_client_context()
        self.assertEqual(under_test.profile_name(), "_PL_API_KEY")
        self.assertIsInstance(under_test.auth_client(), planet_auth.StaticApiKeyAuthClient)
        self.assertEqual(under_test._auth_client._auth_client_config.lazy_get("api_key"), "PLAK_env_API_key")
        self.assertIsNone(under_test.token_file_path())

    def test_init_from_explicit_profile(self):
        # Conflicting config from the env that should be ignored:
        self.write_test_conf_file(
            {
                EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ[EnvironmentVariables.AUTH_PROFILE] = PROFILE1_NAME
        os.environ[EnvironmentVariables.AUTH_CLIENT_ID] = "unit_test_env_client_id"
        os.environ[EnvironmentVariables.AUTH_CLIENT_SECRET] = "unit_test_env_client_secret"
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"

        under_test = PlanetAuthFactory.initialize_auth_client_context(auth_profile_opt=PROFILE2_NAME)
        self.assertEqual(under_test.profile_name(), PROFILE2_NAME)
        # self.assertIsInstance(under_test.auth_client(), planet_auth.XXX)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_explicit_profile_unknown(self):
        # Conflicting config from the env that should be ignored:
        self.write_test_conf_file(
            {
                EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ[EnvironmentVariables.AUTH_PROFILE] = PROFILE1_NAME
        os.environ[EnvironmentVariables.AUTH_CLIENT_ID] = "unit_test_env_client_id"
        os.environ[EnvironmentVariables.AUTH_CLIENT_SECRET] = "unit_test_env_client_secret"
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"

        with self.assertRaises(FileNotFoundError):  # as context:
            PlanetAuthFactory.initialize_auth_client_context(auth_profile_opt="Unit-Test-Unknown-Profile")

    def test_init_from_explicit_oauth_m2m(self):
        # Conflicting config from the env that should be ignored:
        self.write_test_conf_file(
            {
                EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ[EnvironmentVariables.AUTH_CLIENT_ID] = "unit_test_env_client_id"
        os.environ[EnvironmentVariables.AUTH_CLIENT_SECRET] = "unit_test_env_client_secret"
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"

        mock_client_id = "test_client_id"
        mock_client_secret = "test_client_secret"
        under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_client_id_opt=mock_client_id,
            auth_client_secret_opt=mock_client_secret,
        )
        self.assertEqual(under_test.profile_name(), f"utest-m2m-{mock_client_id}")
        self.assertEqual(under_test._auth_client._auth_client_config.lazy_get("client_id"), "test_client_id")
        self.assertEqual(under_test._auth_client._auth_client_config.lazy_get("client_secret"), "test_client_secret")
        self.assertIsInstance(under_test.auth_client(), planet_auth.ClientCredentialsClientSecretAuthClient)
        self.assertIsNotNone(under_test.token_file_path())

    def test_init_from_explicit_api_key(self):
        # Conflicting config from the env that should be ignored:
        self.write_test_conf_file(
            {
                EnvironmentVariables.AUTH_PROFILE: PROFILE3_NAME,  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_ID: "unit_test_conffile_client_id",  # Lower priority
                EnvironmentVariables.AUTH_CLIENT_SECRET: "unit_test_conffile_client_secret",  # Lower priority
                EnvironmentVariables.AUTH_API_KEY: "PLAK_conffile_API_key",  # Lower priority
            }
        )
        os.environ[EnvironmentVariables.AUTH_PROFILE] = PROFILE1_NAME
        os.environ[EnvironmentVariables.AUTH_CLIENT_ID] = "unit_test_env_client_id"
        os.environ[EnvironmentVariables.AUTH_CLIENT_SECRET] = "unit_test_env_client_secret"
        os.environ[EnvironmentVariables.AUTH_API_KEY] = "PLAK_env_API_key"

        under_test = PlanetAuthFactory.initialize_auth_client_context(auth_api_key_opt="PLAK_TestApiKey")
        self.assertEqual(under_test.profile_name(), "_PL_API_KEY")
        self.assertEqual(under_test._auth_client._auth_client_config.lazy_get("api_key"), "PLAK_TestApiKey")
        self.assertIsInstance(under_test.auth_client(), planet_auth.StaticApiKeyAuthClient)
        self.assertIsNone(under_test.token_file_path())

    def test_token_file_override(self):
        default_under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt=PROFILE1_NAME,
        )
        default_profile_token_file_path = default_under_test.token_file_path()
        self.assertIsNotNone(default_profile_token_file_path)

        requested_override_token_file_path = default_profile_token_file_path.with_suffix(".override-filename")
        override_under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt=PROFILE1_NAME, token_file_opt=str(requested_override_token_file_path)
        )
        self.assertEqual(requested_override_token_file_path, override_under_test.token_file_path())

    def test_in_memory_token_file(self):
        token_saved_to_disk_under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt=PROFILE1_NAME, save_token_file=True
        )
        self.assertIsNotNone(token_saved_to_disk_under_test.token_file_path())

        token_in_memory_only_under_test = PlanetAuthFactory.initialize_auth_client_context(
            auth_profile_opt=PROFILE1_NAME, save_token_file=False
        )
        self.assertIsNone(token_in_memory_only_under_test.token_file_path())

    def test_save_profile_saves_when_true(self):
        utest_profile_name = "new-utest-profile-save"
        client_conf_storage_path = Profile.get_profile_file_path(
            profile=utest_profile_name, filename=AUTH_CONFIG_FILE_PLAIN
        )
        self.assertFalse(self.under_test_storage_provider.obj_exists(client_conf_storage_path))

        _ = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config={
                "client_type": "oidc_client_credentials_secret",
                "auth_server": "https://login-utest.planet.com/",
                "audiences": ["https://utest.planet.com/"],
                "client_id": "__UTEST_CLIENT_ID__",
                "client_secret": "__UTEST_CLIENT_SECRET__",
            },
            save_token_file=True,
            save_profile_config=True,
            profile_name=utest_profile_name,
        )
        self.assertTrue(
            self.under_test_storage_provider.obj_exists(
                Profile.get_profile_file_path(profile=utest_profile_name, filename=AUTH_CONFIG_FILE_PLAIN)
            )
        )

    def test_save_profile_does_not_save_when_false(self):
        utest_profile_name = "new-utest-profile-nosave"
        client_conf_storage_path = Profile.get_profile_file_path(
            profile=utest_profile_name, filename=AUTH_CONFIG_FILE_PLAIN
        )
        self.assertFalse(self.under_test_storage_provider.obj_exists(client_conf_storage_path))

        _ = PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
            client_config={
                "client_type": "oidc_client_credentials_secret",
                "auth_server": "https://login-utest.planet.com/",
                "audiences": ["https://utest.planet.com/"],
                "client_id": "__UTEST_CLIENT_ID__",
                "client_secret": "__UTEST_CLIENT_SECRET__",
            },
            save_token_file=False,
            save_profile_config=False,
            profile_name=utest_profile_name,
        )
        self.assertFalse(
            self.under_test_storage_provider.obj_exists(
                Profile.get_profile_file_path(profile=utest_profile_name, filename=AUTH_CONFIG_FILE_PLAIN)
            )
        )


ISSUER_PRIORITIES = ["_trusted"]
VALID_PRIMARY_CONFIGS = [
    {
        "auth_server": "https://login-fake.planet.com/oauth2/auth_server_id",
        "audiences": ["https://api.staging.planet-labs.com/"],
    }
]
VALID_SECONDARY_CONFIGS = [
    {
        "auth_server": "https://login-fake.planet.com/oauth2/deprecated_auth_server_id",
        "audiences": ["https://api.staging.planet-labs.com/"],
    }
]
INVALID_PRIMARY_CONFIGS = [{"auth_server": "https://login-fake.planet.com/oauth2/auth_server_id"}]


class TestResourceServerValidatorInitHelper(TestWithHomeDirProfiles, unittest.TestCase):
    def setUp(self):
        os.environ[AUTH_BUILTIN_PROVIDER] = (
            "tests.test_planet_auth_utils.unit.auth_utils.builtins_test_impl.BuiltinConfigurationProviderMockTestImpl"
        )
        Builtins._builtin = None  # Reset built-in state.
        self.setUp_testHomeDir()
        os.environ.pop(EnvironmentVariables.AUTH_PROFILE, None)
        os.environ.pop(EnvironmentVariables.AUTH_API_KEY, None)
        os.environ.pop(EnvironmentVariables.AUTH_CLIENT_ID, None)
        os.environ.pop(EnvironmentVariables.AUTH_CLIENT_SECRET, None)

    def tearDown(self) -> None:
        self.tearDown_testHomeDir()

    def _check_validator_equality(self, validator_1, validator_2):
        validator_1_vars = vars(validator_1)
        validator_2_vars = vars(validator_2)

        # Check the issuers
        for priority in ISSUER_PRIORITIES:
            self.assertEqual(validator_1_vars[priority].keys(), validator_2_vars[priority].keys())

    def test_staging(self):
        validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
            MockStagingEnv.TRUSTED_OAUTH_AUTHORITIES,
        )
        test_validator = PlanetAuthFactory.initialize_resource_server_validator("STAGING")
        self._check_validator_equality(validator, test_validator)

    def test_prod(self):
        validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
            MockProductionEnv.TRUESTED_OAUTH_AUTHORITIES,
        )
        test_validator = PlanetAuthFactory.initialize_resource_server_validator("PRODUCTION")
        self._check_validator_equality(validator, test_validator)

    def test_custom_valid_configs(self):
        test_validator = PlanetAuthFactory.initialize_resource_server_validator("CUSTOM", VALID_PRIMARY_CONFIGS)
        test_validator_vars = vars(test_validator)

        # Check if the issuers match the passed custom configuration
        for priority, config in zip(ISSUER_PRIORITIES, [VALID_PRIMARY_CONFIGS, VALID_SECONDARY_CONFIGS]):
            issuers = list(test_validator_vars[priority].keys())
            self.assertEqual(len(issuers), 1)
            self.assertEqual(issuers[0], config[0]["auth_server"])

    def test_custom_invalid_configs(self):
        with self.assertRaises(planet_auth.AuthException) as context:
            PlanetAuthFactory.initialize_resource_server_validator("CUSTOM", INVALID_PRIMARY_CONFIGS)
        self.assertEqual(
            str(context.exception),
            "Auth Providers used for OIDC token validation must have the audiences configuration value set.",
        )

    def test_custom_null_configs(self):
        with self.assertRaises(MissingArgumentException) as context:
            PlanetAuthFactory.initialize_resource_server_validator("CUSTOM", None)
        self.assertEqual(
            str(context.exception),
            "Custom or unknown environment was selected, but trusted_auth_server_configs was not supplied.",
        )

    def test_not_custom_with_configs(self):
        with self.assertWarns(UserWarning) as context:
            test_validator = PlanetAuthFactory.initialize_resource_server_validator("STAGING", VALID_PRIMARY_CONFIGS)
        self.assertEqual(
            len(context.warnings), 1, f"Expected exactly 1 warning, but got {len(context.warnings)} warnings."
        )
        self.assertEqual(
            str(context.warnings[0].message),
            "Custom environment not selected; trusted_auth_server_configs will be ignored in favor of the built in configuration for STAGING.",
        )

        validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
            MockStagingEnv.TRUSTED_OAUTH_AUTHORITIES,
        )
        self._check_validator_equality(validator, test_validator)

    def test_environment_case_insensitivity(self):
        validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
            MockStagingEnv.TRUSTED_OAUTH_AUTHORITIES,
        )
        test_validator = PlanetAuthFactory.initialize_resource_server_validator("sTaGinG")
        self._check_validator_equality(validator, test_validator)

    def test_unknown_environment(self):
        invalid_environment = "Omicron Persei 8"
        with self.assertRaises(ValueError) as context:
            PlanetAuthFactory.initialize_resource_server_validator(invalid_environment)
        self.assertEqual(
            str(context.exception),
            f"Passed environment must be one of {Builtins.builtin_environment_names()}. Instead, got: {invalid_environment.upper()}",
        )

    def test_unset_environment_1(self):
        with self.assertRaises(ValueError) as context:
            PlanetAuthFactory.initialize_resource_server_validator("")
        self.assertEqual(
            str(context.exception),
            f"Passed environment must be one of {Builtins.builtin_environment_names()}.",
        )

    def test_unset_environment_2(self):
        with self.assertRaises(ValueError) as context:
            PlanetAuthFactory.initialize_resource_server_validator(None)
        self.assertEqual(
            str(context.exception),
            f"Passed environment must be one of {Builtins.builtin_environment_names()}.",
        )
