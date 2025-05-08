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

from planet_auth.oidc.api_clients.device_authorization_api_client import (
    DeviceAuthorizationApiClient,
    DeviceAuthorizationApiException,
)

TEST_CLIENT_ID = "unittest_client_id"
TEST_API_ENDPOINT = "https://blackhole.unittest.planet.com/device_auth"

RESPONSE_VALID = {
    "device_code": "mock_device_code",
    "user_code": "mock_user_code",
    "verification_uri": "https://blackhole.unittest.planet.com/verify",
    "expires_in": 100,
}

RESPONSE_ERROR = {
    "errorCode": "invalid_client",
    "errorSummary": "Invalid value for 'client_id' parameter.",
    "errorLink": "invalid_client",
    "errorId": "oaxxxxzvfUZSabcdJmohb1234",
}

RESPONSE_INVALID_MISSING_DEVICE_CODE = RESPONSE_VALID.copy()
RESPONSE_INVALID_MISSING_DEVICE_CODE.pop("device_code")

RESPONSE_INVALID_MISSING_USER_CODE = RESPONSE_VALID.copy()
RESPONSE_INVALID_MISSING_USER_CODE.pop("user_code")

RESPONSE_INVALID_MISSING_VERIFICATION_URI = RESPONSE_VALID.copy()
RESPONSE_INVALID_MISSING_VERIFICATION_URI.pop("verification_uri")

RESPONSE_INVALID_MISSING_EXPIRES_IN = RESPONSE_VALID.copy()
RESPONSE_INVALID_MISSING_EXPIRES_IN.pop("expires_in")


def mocked_request_valid(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(RESPONSE_VALID))
    return response


def mocked_request_invalid_missing_device_code(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(RESPONSE_INVALID_MISSING_DEVICE_CODE))
    return response


def mocked_request_invalid_missing_user_code(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(RESPONSE_INVALID_MISSING_USER_CODE))
    return response


def mocked_request_invalid_missing_verification_uri(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(RESPONSE_INVALID_MISSING_VERIFICATION_URI))
    return response


def mocked_request_invalid_missing_expires_in(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(RESPONSE_INVALID_MISSING_EXPIRES_IN))
    return response


def noop_auth_enricher(raw_payload: dict, audience: str) -> Tuple[dict, Optional[AuthBase]]:
    return raw_payload, None


class DeviceAuthorizationApiClientTest(unittest.TestCase):
    @mock.patch("requests.sessions.Session.post", side_effect=mocked_request_valid)
    def test_request_device_code(self, mock_post):
        under_test = DeviceAuthorizationApiClient(device_authorization_uri=TEST_API_ENDPOINT)
        under_test.request_device_code(
            client_id=TEST_CLIENT_ID,
            requested_scopes=None,
            requested_audiences=None,
            auth_enricher=noop_auth_enricher,
            extra=None,
        )
        # No exception is a passed test

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_request_invalid_missing_device_code)
    def test_request_device_code_missing_device_code(self, mock_post):
        under_test = DeviceAuthorizationApiClient(device_authorization_uri=TEST_API_ENDPOINT)
        with self.assertRaises(DeviceAuthorizationApiException):
            under_test.request_device_code(
                client_id=TEST_CLIENT_ID,
                requested_scopes=["utest_scope_1"],
                requested_audiences=["utest_audience"],
                auth_enricher=None,
                extra=None,
            )

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_request_invalid_missing_user_code)
    def test_request_device_code_missing_user_code(self, most_post):
        under_test = DeviceAuthorizationApiClient(device_authorization_uri=TEST_API_ENDPOINT)
        with self.assertRaises(DeviceAuthorizationApiException):
            under_test.request_device_code(
                client_id=TEST_CLIENT_ID,
                requested_scopes=["utest_scope_1"],
                requested_audiences=["utest_audience"],
                auth_enricher=None,
                extra=None,
            )

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_request_invalid_missing_verification_uri)
    def test_request_device_code_missing_verification_uri(self, mock_post):
        under_test = DeviceAuthorizationApiClient(device_authorization_uri=TEST_API_ENDPOINT)
        with self.assertRaises(DeviceAuthorizationApiException):
            under_test.request_device_code(
                client_id=TEST_CLIENT_ID,
                requested_scopes=["utest_scope_1"],
                requested_audiences=["utest_audience"],
                auth_enricher=None,
                extra=None,
            )

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_request_invalid_missing_expires_in)
    def test_request_device_code_missing_expires_in(self, mock_post):
        under_test = DeviceAuthorizationApiClient(device_authorization_uri=TEST_API_ENDPOINT)
        with self.assertRaises(DeviceAuthorizationApiException):
            under_test.request_device_code(
                client_id=TEST_CLIENT_ID,
                requested_scopes=["utest_scope_1"],
                requested_audiences=["utest_audience"],
                auth_enricher=None,
                extra=None,
            )
