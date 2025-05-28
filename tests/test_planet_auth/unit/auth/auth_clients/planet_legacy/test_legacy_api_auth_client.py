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

import json
import pathlib
import unittest

from requests.models import Response
from unittest import mock

from planet_auth.auth_client import AuthClientConfigException
from planet_auth.planet_legacy.auth_client import (
    PlanetLegacyAuthClient,
    PlanetLegacyAuthClientConfig,
    PlanetLegacyAuthClientException,
)
from planet_auth.planet_legacy.legacy_api_key import FileBackedPlanetLegacyApiKey
from planet_auth.planet_legacy.request_authenticator import PlanetLegacyRequestAuthenticator
from tests.test_planet_auth.unit.auth.util import TestTokenBuilder
from tests.test_planet_auth.util import load_rsa_private_key, tdata_resource_file_path

TEST_MOCK_API_KEY = "PLAK_MockApiKey"
TEST_MOCK_API_KEY2 = "PLAK_MockApiKey2"
TEST_AUTH_ENDPOINT = "https://blackhole.unittest.planet.com/legacy_auth"
TEST_BAD_RESPONSE = {"some_key": "some bogus response payload"}
TEST_TOKEN_TTL = 60

TEST_SIGNING_KEY = load_rsa_private_key(tdata_resource_file_path("keys/keypair1_priv_nopassword.test_pem"))

TOKEN_BUILDER = TestTokenBuilder(
    issuer="__test_token_issuer__",
    audience="__test_token_audience__",
    signing_key_file=tdata_resource_file_path("keys/keypair1_priv_nopassword.test_pem"),
)


def generate_response_struct(token_str):
    response_struct = {"token": token_str}
    return response_struct


def mock_response_valid(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(
        json.dumps(
            generate_response_struct(
                TOKEN_BUILDER.generate_legacy_token(api_key=TEST_MOCK_API_KEY, ttl=TEST_TOKEN_TTL)
            )
        )
    )
    return response


def mock_response_http_error(request_url, **kwargs):
    response = Response()
    response.status_code = 401
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps({"error": "access denied"}))
    return response


def mock_response_empty_payload(request_url, **kwargs):
    response = Response()
    response.status_code = 202
    return response


def mock_response_bad_content_type(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "text/plain"
    response._content = str.encode("Plain sting response")
    return response


def mock_response_no_token_in_payload(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps({"foo": "this test payload lacks a token"}))
    return response


def mock_response_bad_token(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(
        json.dumps(generate_response_struct(TOKEN_BUILDER.generate_legacy_token(api_key=None, ttl=TEST_TOKEN_TTL)))
    )
    return response


def mocked_getpass_password(**kwargs):
    return "mock_getpass_password"


def mocked_input_username(prompt, **kwargs):
    return "mock_input_username"


class TestLecaycApiAuthClientConfig(unittest.TestCase):
    def test_check(self):
        under_test = PlanetLegacyAuthClientConfig(api_key=TEST_MOCK_API_KEY, legacy_auth_endpoint=TEST_AUTH_ENDPOINT)
        under_test.check()  # should not throw

        under_test = PlanetLegacyAuthClientConfig(api_key=TEST_MOCK_API_KEY)
        with self.assertRaises(AuthClientConfigException):
            under_test.check()


class TestLegacyApiAuthClient(unittest.TestCase):
    def setUp(self):
        self.under_test_no_apikey_in_conf_in_memory = PlanetLegacyAuthClient(
            PlanetLegacyAuthClientConfig(legacy_auth_endpoint=TEST_AUTH_ENDPOINT)
        )
        self.under_test_with_apikey_in_memory = PlanetLegacyAuthClient(
            PlanetLegacyAuthClientConfig(legacy_auth_endpoint=TEST_AUTH_ENDPOINT, api_key=TEST_MOCK_API_KEY2)
        )
        self.under_test_with_apikey_from_file_conf_path = tdata_resource_file_path(
            "auth_client_configs/utest/planet_legacy_with_apikey.json"
        )
        self.under_test_with_apikey_from_file = PlanetLegacyAuthClient(
            PlanetLegacyAuthClientConfig(file_path=self.under_test_with_apikey_from_file_conf_path)
        )

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_valid)
    def test_login_success_direct_input(self, mock1):
        test_result = self.under_test_no_apikey_in_conf_in_memory.login(username="test_user", password="test_password")
        self.assertIsInstance(test_result, FileBackedPlanetLegacyApiKey)
        self.assertEqual(TEST_MOCK_API_KEY, test_result.legacy_api_key())

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_valid)
    @mock.patch("getpass.getpass", mocked_getpass_password)
    @mock.patch("builtins.input", mocked_input_username)
    def test_login_success_user_prompt(self, mock1):
        test_result = self.under_test_no_apikey_in_conf_in_memory.login(allow_tty_prompt=True)
        self.assertIsInstance(test_result, FileBackedPlanetLegacyApiKey)
        self.assertEqual(TEST_MOCK_API_KEY, test_result.legacy_api_key())

    def test_login_failure_username_input_needed(self):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(
                username=None, password="test_password", allow_tty_prompt=False
            )

    def test_login_failure_password_input_needed(self):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(
                username="test_user", password=None, allow_tty_prompt=False
            )

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_http_error)
    def test_login_http_error(self, mock1):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(username="test_user", password="test_password")

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_empty_payload)
    def test_login_bad_response_no_payload(self, mock1):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(username="test_user", password="test_password")

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_bad_content_type)
    def test_login_bad_response_not_json(self, mock1):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(username="test_user", password="test_password")

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_no_token_in_payload)
    def test_login_bad_response_no_token(self, mock1):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(username="test_user", password="test_password")

    @mock.patch("requests.sessions.Session.post", side_effect=mock_response_bad_token)
    def test_login_bad_response_token_lacks_api_key(self, mock1):
        with self.assertRaises(PlanetLegacyAuthClientException):
            self.under_test_no_apikey_in_conf_in_memory.login(username="test_user", password="test_password")

    def test_default_request_authenticator_when_login(self):
        test_result = self.under_test_no_apikey_in_conf_in_memory.default_request_authenticator(
            credential=pathlib.Path("/test/token.json")
        )
        self.assertIsInstance(test_result, PlanetLegacyRequestAuthenticator)
        self.assertEqual(pathlib.Path("/test/token.json"), test_result._credential.path())

    def test_default_request_authenticator_when_apikey_in_client_config_from_file(self):
        test_result = self.under_test_with_apikey_from_file.default_request_authenticator(
            credential=pathlib.Path("/test/token.json")
        )
        self.assertIsInstance(test_result, PlanetLegacyRequestAuthenticator)
        self.assertEqual(PlanetLegacyRequestAuthenticator.TOKEN_PREFIX, test_result._token_prefix)
        self.assertEqual("__utest_legacy_api_key_in_client_config_file__", test_result._credential.legacy_api_key())
        self.assertIsNone(test_result._token_body)  # Loaded JIT
        test_result.pre_request_hook()
        self.assertEqual("__utest_legacy_api_key_in_client_config_file__", test_result._token_body)
        self.assertEqual(self.under_test_with_apikey_from_file_conf_path, test_result._credential.path())

    def test_default_request_authenticator_when_apikey_in_client_config_in_memory(self):
        test_result = self.under_test_with_apikey_in_memory.default_request_authenticator(
            credential=pathlib.Path("/test/token.json")
        )
        self.assertIsInstance(test_result, PlanetLegacyRequestAuthenticator)
        self.assertEqual(PlanetLegacyRequestAuthenticator.TOKEN_PREFIX, test_result._token_prefix)
        self.assertEqual(TEST_MOCK_API_KEY2, test_result._credential.legacy_api_key())
        self.assertIsNone(test_result._token_body)  # Loaded JIT
        test_result.pre_request_hook()
        self.assertEqual(TEST_MOCK_API_KEY2, test_result._token_body)
        self.assertEqual(None, test_result._credential.path())

    def test_default_request_authenticator_given_literal_credential_object_instead_of_path(self):
        literal_credential = FileBackedPlanetLegacyApiKey(api_key="literal_utest_api_credential")
        test_result = self.under_test_no_apikey_in_conf_in_memory.default_request_authenticator(
            credential=literal_credential
        )
        test_result.pre_request_hook()
        self.assertEqual("literal_utest_api_credential", test_result._token_body)
