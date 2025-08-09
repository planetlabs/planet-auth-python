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
import importlib.resources as resources
import logging
import pytest
import requests
import unittest
import urllib.parse

from unittest import mock
from urllib.parse import urlparse, parse_qs

from planet_auth.oidc.api_clients.authorization_api_client import (
    AuthorizationApiClient,
    AuthorizationApiException,
    _parse_authcode_from_callback,
)
from planet_auth.oidc.util import create_pkce_challenge_verifier_pair
from tests.test_planet_auth.util import background, find_free_port, is_cicd

REQUEST_TIMEOUT = 100
TEST_API_ENDPOINT = "https://blackhole.unittest.planet.com/api"
TEST_CLIENT_ID = "_client_id_"
TEST_REDIRECT_URI_TEMPLATE = "http://localhost:{}/utest_callback_uri"
TEST_REQUESTED_SCOPES = ["scope1", "scope2"]
TEST_REQUESTED_AUDIENCES = ["aud1"]
MOCK_AUTHCODE = "_mock_authcode_"
API_RESPONSE_VALID = {}
API_RESPONSE_FAILED = {}
TEST_VERIFIER, TEST_CHALLENGE = create_pkce_challenge_verifier_pair()

logger = logging.getLogger(__name__)


def mocked_get_password(**kwargs):
    return MOCK_AUTHCODE


def mocked_generate_nonce(length):
    # Need to defeat the cryptographic nonce for some tests.
    nonce_charset = "1234567890abcdefghijklmnopqrstuvwxyz"
    return "".join([str(nonce_charset[i % 36]) for i in range(length)])


@background
def fire_and_forget_http_get(url):
    requests.get(url, timeout=REQUEST_TIMEOUT)


def mocked_browser_authserver(request_url, arg2, **kwargs):
    # TODO: assert it's constructed the way we want? The only real
    #       branching in the code under test is handling of scopes
    #       At some point, validating this URL is partially implementing
    #       an authorization server
    parsed_query_string = parse_qs(urlparse(request_url).query)
    redirect_uri = parsed_query_string.get("redirect_uri")[0]
    state = parsed_query_string.get("state")[0]
    encoded_params = urllib.parse.urlencode({"state": state, "code": MOCK_AUTHCODE})
    callback_uri = "{}?{}".format(redirect_uri, encoded_params)

    # I don't care about the result, so run in the background and forget.
    # Against a live auth service, this callback would be called by the
    # browser after an exchange with th auth server and a final redirect.
    # Mocking the browser mocks the auth server interaction
    fire_and_forget_http_get(callback_uri)


class CallbackHandlerTest(unittest.TestCase):
    # There is really no branching logic in this class other than a logging
    # handler. It's purpose in life is to recapture the flow from the browser
    # and save that data for all the other code, which should already have
    # test coverage elsewhere.
    pass


class AuthcodeCallbackParserTest(unittest.TestCase):
    def setUp(self):
        self.under_test = _parse_authcode_from_callback
        self.dummy_callback_baseurl = TEST_REDIRECT_URI_TEMPLATE.format(8080)

    def test_empty_request_throws(self):
        with self.assertRaises(AuthorizationApiException):
            self.under_test(None, None)

        with self.assertRaises(AuthorizationApiException):
            self.under_test("", None)

    def test_explicit_error_throws(self):
        encoded_params = urllib.parse.urlencode({"error": "test_error_1"})
        callback_uri = "{}?{}".format(self.dummy_callback_baseurl, encoded_params)
        with self.assertRaises(AuthorizationApiException):
            self.under_test(callback_uri, None)

        # Mix it up. We want a failure whenever there is an error, even if
        # there is also an auth code (this really shouldn't ever happen).
        encoded_params = urllib.parse.urlencode(
            {
                "error": "test_error_2",
                "error_description": "test error description",
                "code": MOCK_AUTHCODE,
                "state": mocked_generate_nonce(8),
            }
        )
        callback_uri = "{}?{}".format(self.dummy_callback_baseurl, encoded_params)
        with self.assertRaises(AuthorizationApiException):
            self.under_test(callback_uri, None)

    # @mock.patch('planet_auth.oidc.util.generate_nonce', mocked_generate_nonce)
    def test_state_is_checked(self):
        test_state_1 = mocked_generate_nonce(8)
        test_state_2 = test_state_1 + "_STATE_IS_CORRUPTED"

        encoded_params = urllib.parse.urlencode({"code": MOCK_AUTHCODE, "state": test_state_1})
        callback_uri = "{}?{}".format(self.dummy_callback_baseurl, encoded_params)
        auth_code = self.under_test(callback_uri, test_state_1)
        self.assertEqual(MOCK_AUTHCODE, auth_code)

        encoded_params = urllib.parse.urlencode({"code": MOCK_AUTHCODE, "state": test_state_2})
        callback_uri = "{}?{}".format(self.dummy_callback_baseurl, encoded_params)
        with self.assertRaises(AuthorizationApiException):
            self.under_test(callback_uri, test_state_1)

    def test_callback_not_understood_throws(self):
        encoded_params = urllib.parse.urlencode({"data1": "some random data"})
        callback_uri = "{}?{}".format(self.dummy_callback_baseurl, encoded_params)
        with self.assertRaises(AuthorizationApiException):
            self.under_test(callback_uri, None)


class AuthorizationApiClientTest(unittest.TestCase):
    def setUp(self):
        self.callback_port = find_free_port()
        self.callback_uri = TEST_REDIRECT_URI_TEMPLATE.format(self.callback_port)
        self.pkce_verifier, self.pkce_challenge = create_pkce_challenge_verifier_pair()

    @pytest.mark.skipif(condition=is_cicd(), reason="Skipping tests that listen on a network port for CI/CD")
    @mock.patch("webbrowser.open", mocked_browser_authserver)
    def test_get_authcode_with_browser_and_listener(self):
        under_test = AuthorizationApiClient(authorization_uri=TEST_API_ENDPOINT)

        # Cover both default and override scope paths
        # TODO: a better test would be to catch the URL that is constructed
        #       and verify it.  A real verification of that URL amounts to
        #       implementing a partial authorization server.
        authcode = under_test.authcode_from_pkce_auth_request_with_browser_and_callback_listener(
            client_id=TEST_CLIENT_ID,
            redirect_uri=self.callback_uri,
            requested_scopes=None,
            requested_audiences=None,
            pkce_code_challenge=self.pkce_challenge,
            extra=None,
        )
        self.assertEqual(MOCK_AUTHCODE, authcode)

        authcode = under_test.authcode_from_pkce_auth_request_with_browser_and_callback_listener(
            client_id=TEST_CLIENT_ID,
            redirect_uri=self.callback_uri,
            requested_scopes=TEST_REQUESTED_SCOPES,
            requested_audiences=TEST_REQUESTED_AUDIENCES,
            pkce_code_challenge=self.pkce_challenge,
            extra=None,
        )
        self.assertEqual(MOCK_AUTHCODE, authcode)

    @mock.patch("http.server.HTTPServer")
    @mock.patch("planet_auth.oidc.api_clients.authorization_api_client._parse_authcode_from_callback")
    @mock.patch("webbrowser.open")
    def test_get_authcode_with_browser_and_listener_unsupported_callback_host(self, mock1, mock2, mock3):
        under_test = AuthorizationApiClient(authorization_uri=TEST_API_ENDPOINT)

        # Only localhost callbacks should be supported by current code
        valid_callback_1 = "http://localhost:{}/test".format(self.callback_port)
        valid_callback_2 = "http://127.0.0.1:{}/test".format(self.callback_port)
        invalid_callback = "https://test.planet.com:443"

        under_test.authcode_from_pkce_auth_request_with_browser_and_callback_listener(
            client_id=TEST_CLIENT_ID,
            redirect_uri=valid_callback_1,
            requested_scopes=None,
            requested_audiences=None,
            pkce_code_challenge=self.pkce_challenge,
            extra=None,
        )

        under_test.authcode_from_pkce_auth_request_with_browser_and_callback_listener(
            client_id=TEST_CLIENT_ID,
            redirect_uri=valid_callback_2,
            requested_scopes=None,
            requested_audiences=None,
            pkce_code_challenge=self.pkce_challenge,
            extra=None,
        )

        with self.assertRaises(AuthorizationApiException):
            under_test.authcode_from_pkce_auth_request_with_browser_and_callback_listener(
                client_id=TEST_CLIENT_ID,
                redirect_uri=invalid_callback,
                requested_scopes=None,
                requested_audiences=None,
                pkce_code_challenge=self.pkce_challenge,
                extra=None,
            )

    @mock.patch("http.server.HTTPServer", spec=http.server.HTTPServer)
    @mock.patch("webbrowser.open")
    def test_get_authcode_with_browser_and_listener_unknown_callback_failure(self, mock1, mock2):
        under_test = AuthorizationApiClient(authorization_uri=TEST_API_ENDPOINT)
        with self.assertRaises(AuthorizationApiException):
            under_test.authcode_from_pkce_auth_request_with_browser_and_callback_listener(
                client_id=TEST_CLIENT_ID,
                redirect_uri=self.callback_uri,
                requested_scopes=None,
                requested_audiences=None,
                pkce_code_challenge=self.pkce_challenge,
                extra=None,
            )

    @mock.patch("getpass.getpass", mocked_get_password)
    def test_get_authcode_without_browser_and_listener(self):
        under_test = AuthorizationApiClient(authorization_uri=TEST_API_ENDPOINT)

        # Cover both default and override scope paths
        # TODO: a better test would be to catch the URL that is constructed
        #       and verify it.  A real verification of that URL amounts to
        #       implementing a partial authorization server.
        authcode = under_test.authcode_from_pkce_auth_request_with_tty_input(
            client_id=TEST_CLIENT_ID,
            redirect_uri=self.callback_uri,
            requested_scopes=None,
            requested_audiences=None,
            pkce_code_challenge=self.pkce_challenge,
            extra=None,
        )
        self.assertEqual(MOCK_AUTHCODE, authcode)

        authcode = under_test.authcode_from_pkce_auth_request_with_tty_input(
            client_id=TEST_CLIENT_ID,
            redirect_uri=self.callback_uri,
            requested_scopes=TEST_REQUESTED_SCOPES,
            requested_audiences=TEST_REQUESTED_AUDIENCES,
            pkce_code_challenge=self.pkce_challenge,
            extra=None,
        )
        self.assertEqual(MOCK_AUTHCODE, authcode)

    def test_callback_acknowledgement_config(self):
        # WARNING
        # this test is a bit clumsy and whitebox, but the blackbox way to get this data out
        # is to have HTTPServer serve it.
        under_test = AuthorizationApiClient(
            authorization_uri=TEST_API_ENDPOINT, authorization_callback_acknowledgement_response_body="literal"
        )
        self.assertEqual(under_test._authorization_callback_acknowledgement_response_body, "literal")

        from planet_auth.oidc import resources as under_test_resources

        resource_str = (
            resources.files(under_test_resources).joinpath("callback_acknowledgement.html").read_text("utf-8")
        )
        under_test = AuthorizationApiClient(
            authorization_uri=TEST_API_ENDPOINT, authorization_callback_acknowledgement_response_body=""
        )
        self.assertEqual(under_test._authorization_callback_acknowledgement_response_body, resource_str)

        under_test = AuthorizationApiClient(
            authorization_uri=TEST_API_ENDPOINT, authorization_callback_acknowledgement_response_body=None
        )
        self.assertEqual(under_test._authorization_callback_acknowledgement_response_body, resource_str)

        under_test = AuthorizationApiClient(authorization_uri=TEST_API_ENDPOINT)
        self.assertEqual(under_test._authorization_callback_acknowledgement_response_body, resource_str)
