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

import http.server

import httpx
import json
import pytest
import requests
import unittest

from planet_auth.auth_exception import AuthException
from planet_auth.constants import X_PLANET_APP_HEADER, X_PLANET_APP
from planet_auth.request_authenticator import ForbiddenRequestAuthenticator, SimpleInMemoryRequestAuthenticator
from planet_auth.static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator
from planet_auth.static_api_key.static_api_key import FileBackedApiKey
from tests.test_planet_auth.util import background, find_free_port, is_cicd, tdata_resource_file_path

TEST_HEADER = "x-test-header"
TEST_PREFIX = "TEST"
TEST_TOKEN = "_test_bearer_token_"
TEST_TIMEOUT = 30


class _UnitTestRequestHandler(http.server.BaseHTTPRequestHandler):
    # def __init__(self, request, address, server):
    #     super().__init__(request, address, server)

    def do_GET(self):
        # Reflect the auth info back so unit test can check it.
        self.send_response(http.HTTPStatus.OK)
        self.send_header("Content-type", "application/json")
        self.end_headers()

        self.server.callback_raw_request_path = self.path
        response_payload = {
            "header_present": bool(self.headers.get(TEST_HEADER)),
            "header_value": self.headers.get(TEST_HEADER),
        }
        self.wfile.write(bytes(json.dumps(response_payload), "utf-8"))


@background
def handle_test_request_background(listen_port):
    # pylint: disable=W0108
    http_server = http.server.HTTPServer(
        ("localhost", listen_port), lambda request, address, server: _UnitTestRequestHandler(request, address, server)
    )
    http_server.timeout = TEST_TIMEOUT
    http_server.handle_request()


@pytest.mark.skipif(condition=is_cicd(), reason="Skipping tests that listen on a network port for CI/CD")
class RequestAuthenticatorNetworkTest(unittest.TestCase):
    def setUp(self):
        self.listen_port = find_free_port()
        handle_test_request_background(self.listen_port)
        self.test_server_url = "http://localhost:{}/test_request_lib".format(self.listen_port)

    def test_requests_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=TEST_PREFIX, auth_header=TEST_HEADER
        )
        response = requests.get(self.test_server_url, auth=under_test, timeout=TEST_TIMEOUT)
        response_json = response.json()
        self.assertTrue(response_json.get("header_present"))
        self.assertEqual(TEST_PREFIX + " " + TEST_TOKEN, response_json.get("header_value"))

    def test_requests_no_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(token_body=None, token_prefix=None, auth_header=None)
        response = requests.get(self.test_server_url, auth=under_test, timeout=TEST_TIMEOUT)
        response_json = response.json()
        self.assertFalse(response_json.get("header_present"))
        self.assertIsNone(response_json.get("header_value"))

    def test_requests_no_prefix(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=None, auth_header=TEST_HEADER
        )
        response = requests.get(self.test_server_url, auth=under_test, timeout=TEST_TIMEOUT)
        response_json = response.json()
        self.assertTrue(response_json.get("header_present"))
        self.assertEqual(TEST_TOKEN, response_json.get("header_value"))

    def test_httpx_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=TEST_PREFIX, auth_header=TEST_HEADER
        )
        response = httpx.get(self.test_server_url, auth=under_test)
        response_json = response.json()
        self.assertTrue(response_json.get("header_present"))
        self.assertEqual(TEST_PREFIX + " " + TEST_TOKEN, response_json.get("header_value"))

    def test_httpx_no_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(token_body=None, token_prefix=None, auth_header=None)
        response = httpx.get(self.test_server_url, auth=under_test)
        response_json = response.json()
        self.assertFalse(response_json.get("header_present"))
        self.assertIsNone(response_json.get("header_value"))

    def test_httpx_no_prefix(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=None, auth_header=TEST_HEADER
        )
        response = httpx.get(self.test_server_url, auth=under_test)
        response_json = response.json()
        self.assertTrue(response_json.get("header_present"))
        self.assertEqual(TEST_TOKEN, response_json.get("header_value"))

    # TODO: add aiohttp support


# The above is a better test, since it exercises how the base class interacts
# with the HTTP client libs requets and httpx and affects the resulting
# network traffic.  But, setting up a listener is problematic in some
# environments.  Testing the base class amounts to little more than testing
# setters. It doesn't validate that it interacts with the other libs to affect
# the network traffic the way we want it it do.  (We maintain this test anyway
# to hit our CI/CD coverage targets.)


def mock_httpx_get(under_test, headers=None):
    request = under_test.auth_flow(httpx._models.Request(url="http://unittest/", method="GET", headers=headers))
    return next(request)


def mock_requests_get(under_test, headers=None):
    request = requests.Request()
    if headers:
        request.headers.update(headers)
    under_test.__call__(request)
    return request


class RequestAuthenticatorNoNetworkTest(unittest.TestCase):
    def test_requests_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=TEST_PREFIX, auth_header=TEST_HEADER
        )
        request = mock_requests_get(under_test)
        self.assertEqual(request.headers[TEST_HEADER], TEST_PREFIX + " " + TEST_TOKEN)

    def test_requests_no_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=None, token_prefix=TEST_PREFIX, auth_header=TEST_HEADER
        )
        request = mock_requests_get(under_test)
        self.assertIsNone(request.headers.get(TEST_HEADER))

    def test_requests_no_prefix(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=None, auth_header=TEST_HEADER
        )
        request = mock_requests_get(under_test)
        self.assertEqual(request.headers[TEST_HEADER], TEST_TOKEN)

    def test_requests_x_planet_app_header_from_lib(self):
        under_test = SimpleInMemoryRequestAuthenticator()
        request = mock_requests_get(under_test)
        self.assertEqual(request.headers[X_PLANET_APP_HEADER], X_PLANET_APP)

    def test_requests_x_planet_app_header_from_app(self):
        under_test = SimpleInMemoryRequestAuthenticator()
        request = mock_requests_get(under_test, headers={X_PLANET_APP_HEADER: "unit-test-planet-client"})
        self.assertEqual(request.headers[X_PLANET_APP_HEADER], "unit-test-planet-client")

    def test_httpx_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=TEST_PREFIX, auth_header=TEST_HEADER
        )
        request = mock_httpx_get(under_test)
        self.assertEqual(request.headers[TEST_HEADER], TEST_PREFIX + " " + TEST_TOKEN)

    def test_httpx_no_auth(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=None, token_prefix=TEST_PREFIX, auth_header=TEST_HEADER
        )
        request = mock_httpx_get(under_test)
        self.assertIsNone(request.headers.get(TEST_HEADER))

    def test_httpx_no_prefix(self):
        under_test = SimpleInMemoryRequestAuthenticator(
            token_body=TEST_TOKEN, token_prefix=None, auth_header=TEST_HEADER
        )
        request = mock_httpx_get(under_test)
        self.assertEqual(request.headers[TEST_HEADER], TEST_TOKEN)

    def test_httpx_x_planet_app_header_from_lib(self):
        under_test = SimpleInMemoryRequestAuthenticator()
        request = mock_httpx_get(under_test)
        self.assertEqual(request.headers[X_PLANET_APP_HEADER], X_PLANET_APP)

    def test_httpx_x_planet_app_header_from_app(self):
        under_test = SimpleInMemoryRequestAuthenticator()
        request = mock_httpx_get(under_test, headers={X_PLANET_APP_HEADER: "unit-test-planet-client"})
        self.assertEqual(request.headers[X_PLANET_APP_HEADER], "unit-test-planet-client")


class ForbiddenRequestAuthenticatorkTest(unittest.TestCase):
    # Since this request authenticator is supposed to pretty much prevent network
    # requests from being made, there is no need for separate Network/NoNetwork test cases.
    def setUp(self):
        self.under_test = ForbiddenRequestAuthenticator()

    def test_requests_auth(self):
        with self.assertRaises(AuthException):
            mock_requests_get(self.under_test)

    def test_httpx_auth(self):
        with self.assertRaises(AuthException):
            mock_httpx_get(self.under_test)


class CredentialRequestAuthenticatorTest(unittest.TestCase):
    def setUp(self) -> None:
        # This is the simplest concrete class that derives from CredentialRequestAuthenticatorTest
        self.test_credential_file_path_1 = tdata_resource_file_path("keys/static_api_key_test_credential.json")
        self.test_credential_file_path_2 = tdata_resource_file_path("keys/static_api_key_test_credential_2.json")
        self.test_credential_1 = FileBackedApiKey(api_key_file=self.test_credential_file_path_1)
        self.test_credential_2 = FileBackedApiKey(api_key_file=self.test_credential_file_path_2)
        self.under_test = FileBackedApiKeyRequestAuthenticator(api_key_credential=self.test_credential_1)

    def test_update_credential(self):
        self.assertIsNone(self.under_test._token_body)
        self.under_test.pre_request_hook()
        self.assertEqual("test_api_key", self.under_test._token_body)

        self.under_test.update_credential(self.test_credential_2)
        self.assertIsNone(self.under_test._token_body)
        self.under_test.pre_request_hook()
        self.assertEqual("test_api_key_2", self.under_test._token_body)
