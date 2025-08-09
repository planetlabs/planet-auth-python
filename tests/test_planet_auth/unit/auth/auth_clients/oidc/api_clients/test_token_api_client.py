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
import unittest

from requests.models import Response
from requests.auth import AuthBase
from typing import Tuple, Optional
from unittest import mock
import freezegun

from planet_auth.oidc.api_clients.api_client import OidcApiClientException
from planet_auth.oidc.api_clients.token_api_client import TokenApiClient, TokenApiException, TokenApiTimeoutException
from planet_auth.oidc.util import create_pkce_challenge_verifier_pair

from tests.test_planet_auth.util import mock_sleep_skip, FreezeGunMockSleep

TEST_API_ENDPOINT = "https://blackhole.unittest.planet.com/api"
TEST_CLIENT_ID = "__test_client_id__"
TEST_REDIRECT_URI = "__test_redirect_uri__"
TEST_ACCESS_TOKEN = "__test_access_token__"
TEST_ID_TOKEN = "__test_id_token__"
TEST_REFRESH_TOKEN = "__test_refresh_token__"
TEST_USER_NAME = "__test_username__"
TEST_USER_PASSWORD = "__test_password__"
API_RESPONSE_VALID = {
    "token_type": "Bearer",
    "expires_in": 3600,
    "access_token": "_dummy_access_token_",
    "scope": "offline_access profile openid",
    "refresh_token": "_dummy_refresh_token_",
    "id_token": "_dummy_id_token_",
}
API_RESPONSE_INVALID = {  # it looks valid, but no "expires_in"
    "token_type": "Bearer",
    "access_token": "_dummy_access_token_",
    "scope": "offline_access profile openid",
    "refresh_token": "_dummy_refresh_token_",
    "id_token": "_dummy_id_token_",
}
API_RESPONSE_PENDING = {
    "error": "authorization_pending",
}
API_RESPONSE_SLOW_DOWN = {
    "error": "slow_down",
}
API_RESPONSE_SERVICE_SIDE_TIMEOUT = {
    "error": "expired_token",
}
API_RESPONSE_DENIED = {
    "error": "access_denied",
}


def mocked_response_ok(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_VALID))
    return response


def mocked_response_invalid(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_INVALID))
    return response


def mocked_response_pending(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_PENDING))
    return response


def mocked_response_slow_down(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_SLOW_DOWN))
    return response


def mocked_response_denied(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_DENIED))
    return response


def mocked_response_pending_then_valid(request_url, **kwargs):
    mocked_response_pending_then_valid.counter += 1
    if mocked_response_pending_then_valid.counter == 2:
        return mocked_response_ok(request_url, **kwargs)
    else:
        return mocked_response_pending(request_url, **kwargs)


mocked_response_pending_then_valid.counter = 0


# def load_privkey():
#     return load_rsa_private_key(
#         tdata_resource_file_path('keys/keypair1_priv.test_pem'), 'password')


class TokenApiClientTest(unittest.TestCase):
    def _test_auth_enricher(self, raw_payload: dict, audience: str) -> Tuple[dict, Optional[AuthBase]]:
        return raw_payload, None

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_authcode_valid(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        pkce_code_verifier, pkce_code_challenge = create_pkce_challenge_verifier_pair()
        token_response = under_test.get_token_from_code(
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_REDIRECT_URI,
            code="dummy_authcode",
            code_verifier=pkce_code_verifier,
        )
        self.assertEqual(API_RESPONSE_VALID, token_response)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_authcode_valid_with_auth_enricher(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        pkce_code_verifier, pkce_code_challenge = create_pkce_challenge_verifier_pair()
        token_response = under_test.get_token_from_code(
            client_id=TEST_CLIENT_ID,
            redirect_uri=TEST_REDIRECT_URI,
            code="dummy_authcode",
            code_verifier=pkce_code_verifier,
            auth_enricher=self._test_auth_enricher,
        )
        self.assertEqual(API_RESPONSE_VALID, token_response)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_client_credentials(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        # private_key = load_privkey()
        token_response = under_test.get_token_from_client_credentials(TEST_CLIENT_ID)
        self.assertEqual(API_RESPONSE_VALID, token_response)
        # Coverage complains when we don't test the custom scopes
        # branch, but the server and it's response is mock, so we
        # don't actually have anything different to check in the result.
        # All we can check is that it didn't throw. Same for audiences.
        under_test.get_token_from_client_credentials(
            TEST_CLIENT_ID,
            requested_scopes=["scope1", "scope2"],
            requested_audiences=["req_audience_1"],
        )

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_refresh_valid(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        token_response = under_test.get_token_from_refresh(TEST_CLIENT_ID, TEST_REFRESH_TOKEN)
        self.assertEqual(API_RESPONSE_VALID, token_response)
        # Coverage complains when we don't test the custom scopes
        # branch, but the server and it's response is mock, so we
        # don't actually have anything different to check in the result.
        # All we can check is that it didn't throw.
        token_response = under_test.get_token_from_refresh(
            TEST_CLIENT_ID, TEST_REFRESH_TOKEN, requested_scopes=["scope1", "scope2"]
        )

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_invalid)
    def test_invalid_response(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        pkce_code_verifier, pkce_code_challenge = create_pkce_challenge_verifier_pair()
        with self.assertRaises(TokenApiException):
            under_test.get_token_from_code(TEST_CLIENT_ID, TEST_REDIRECT_URI, "dummy_authcode", pkce_code_verifier)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_password(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        token_response = under_test.get_token_from_password(
            client_id=TEST_CLIENT_ID, username=TEST_USER_NAME, password=TEST_USER_PASSWORD
        )
        self.assertEqual(API_RESPONSE_VALID, token_response)
        # Coverage complains when we don't test the custom scopes
        # branch, but the server and it's response is mock, so we
        # don't actually have anything different to check in the result.
        # All we can check is that it didn't throw. Same for audiences.
        under_test.get_token_from_password(
            client_id=TEST_CLIENT_ID,
            username=TEST_USER_NAME,
            password=TEST_USER_PASSWORD,
            requested_scopes=["scope1", "scope2"],
            requested_audiences=["req_audience_1"],
        )

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_password_with_auth_enricher(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        token_response = under_test.get_token_from_password(
            client_id=TEST_CLIENT_ID,
            username=TEST_USER_NAME,
            password=TEST_USER_PASSWORD,
            auth_enricher=self._test_auth_enricher,
        )
        self.assertEqual(API_RESPONSE_VALID, token_response)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_token_from_device_code(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        token_response = under_test.poll_for_token_from_device_code(
            client_id=TEST_CLIENT_ID,
            device_code="__utest_mock_device_code__",
            timeout=8,
            poll_interval=1,
            auth_enricher=self._test_auth_enricher,
        )
        self.assertEqual(API_RESPONSE_VALID, token_response)

    @mock.patch("time.sleep", mock_sleep_skip)
    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_pending_then_valid)
    def test_token_from_device_code_pending_then_ok(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        token_response = under_test.poll_for_token_from_device_code(
            client_id=TEST_CLIENT_ID,
            device_code="__utest_mock_device_code__",
            timeout=8,
            poll_interval=1,
            auth_enricher=self._test_auth_enricher,
        )
        self.assertEqual(API_RESPONSE_VALID, token_response)
        self.assertEqual(mock_post.call_count, 2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_slow_down)
    def test_token_from_device_code_slow_down(self, mock_post, frozen_time):
        fg_mock_sleep = FreezeGunMockSleep(frozen_time)
        with mock.patch("time.sleep", side_effect=fg_mock_sleep.mock_sleep):
            under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
            with self.assertRaises(TokenApiTimeoutException):
                under_test.poll_for_token_from_device_code(
                    client_id=TEST_CLIENT_ID,
                    device_code="__utest_mock_device_code__",
                    timeout=16,
                    poll_interval=1,
                    auth_enricher=self._test_auth_enricher,
                )

            # A bit loose of a check. We expect a slow-down of +5 seconds each time
            # the service tells us to slow down. Our mock is simple and always tells us
            # to slow, and we exit with the client provided timeout.
            # So, we expect sleeps/checks at t = 1, 6, 11, <timeout>
            self.assertEqual(mock_post.call_count, 3)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_pending)
    def test_token_from_device_code_client_provided_timeout(self, mock_post, frozen_time):
        fg_mock_sleep = FreezeGunMockSleep(frozen_time)
        with mock.patch("time.sleep", side_effect=fg_mock_sleep.mock_sleep):
            under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
            with self.assertRaises(TokenApiException):
                under_test.poll_for_token_from_device_code(
                    client_id=TEST_CLIENT_ID,
                    device_code="__utest_mock_device_code__",
                    timeout=4,
                    poll_interval=1,
                    auth_enricher=self._test_auth_enricher,
                )
            # a bit loose of a check?
            self.assertEqual(mock_post.call_count, 5)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_denied)
    def test_token_from_device_code_service_generated_error(self, mock_post):
        under_test = TokenApiClient(token_uri=TEST_API_ENDPOINT)
        with self.assertRaises(OidcApiClientException):
            under_test.poll_for_token_from_device_code(
                client_id=TEST_CLIENT_ID,
                device_code="__utest_mock_device_code__",
                timeout=4,
                poll_interval=1,
                auth_enricher=self._test_auth_enricher,
            )
        self.assertEqual(mock_post.call_count, 1)
