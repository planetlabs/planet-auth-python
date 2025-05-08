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

from requests.auth import AuthBase
from requests.models import Response
from typing import Tuple, Optional
from unittest import mock

from planet_auth.oidc.api_clients.introspect_api_client import (
    IntrospectionApiClient,
    IntrospectionApiException,
    IntrospectionRejectionTokenException,
)

TEST_API_ENDPOINT = "https://blackhole.unittest.planet.com/introspect"
TEST_ACCESS_TOKEN = "__test_access_token__"
TEST_ID_TOKEN = "__test_id_token__"
TEST_REFRESH_TOKEN = "__test_refresh_token__"
INTROSPECTION_RESPONSE_VALID = {
    "active": True,
    "scope": "offline_access profile openid",
    "username": "mock_test_user@planet.com",
    "exp": 1651255371,
    "iat": 1651251771,
    "sub": "mock_test_user@planet.com",
    "aud": "https://api.planet.com/mock_audience",
    "iss": "https://account.planet.com/mock_issuer",
    "jti": "mock_token_id",
    "token_type": "Bearer",
    "client_id": "mock_client_id",
    "uid": "mock_user_id",
    "api_key": "PLAK_MyKey",
    "user_id": 123456,
    "organization_id": 1,
    "role_level": 100,
}
INTROSPECTION_RESPONSE_FAILED = {"active": False}

INTROSPECTION_RESPONSE_INVALID1 = {
    ## Invalid - "active" field is not boolean. Even though this says active: true,
    ## the format is not valid and validation should fail.
    "active": "True",
    "scope": "offline_access profile openid",
    "username": "mock_test_user@planet.com",
    "exp": 1651255371,
    "iat": 1651251771,
    "sub": "mock_test_user@planet.com",
    "aud": "https://api.planet.com/mock_audience",
    "iss": "https://account.planet.com/mock_issuer",
    "jti": "mock_token_id",
    "token_type": "Bearer",
    "client_id": "mock_client_id",
    "uid": "mock_user_id",
    "api_key": "PLAK_MyKey",
    "user_id": 123456,
    "organization_id": 1,
    "role_level": 100,
}

INTROSPECTION_RESPONSE_INVALID2 = {
    ## Invalid - "active" field is not boolean
    "active": "False",
    "scope": "offline_access profile openid",
    "username": "mock_test_user@planet.com",
    "exp": 1651255371,
    "iat": 1651251771,
    "sub": "mock_test_user@planet.com",
    "aud": "https://api.planet.com/mock_audience",
    "iss": "https://account.planet.com/mock_issuer",
    "jti": "mock_token_id",
    "token_type": "Bearer",
    "client_id": "mock_client_id",
    "uid": "mock_user_id",
    "api_key": "PLAK_MyKey",
    "user_id": 123456,
    "organization_id": 1,
    "role_level": 100,
}

INTROSPECTION_RESPONSE_INVALID3 = {
    ## Invalid - "active" field is missing
    "scope": "offline_access profile openid",
    "username": "mock_test_user@planet.com",
    "exp": 1651255371,
    "iat": 1651251771,
    "sub": "mock_test_user@planet.com",
    "aud": "https://api.planet.com/mock_audience",
    "iss": "https://account.planet.com/mock_issuer",
    "jti": "mock_token_id",
    "token_type": "Bearer",
    "client_id": "mock_client_id",
    "uid": "mock_user_id",
    "api_key": "PLAK_MyKey",
    "user_id": 123456,
    "organization_id": 1,
    "role_level": 100,
}


def noop_auth_enricher(raw_payload: dict, audience: str) -> Tuple[dict, Optional[AuthBase]]:
    return raw_payload, None


def mocked_validate_ok(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(INTROSPECTION_RESPONSE_VALID))
    return response


def mocked_validate_fail(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(INTROSPECTION_RESPONSE_FAILED))
    return response


def mocked_validate_invalid1(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(INTROSPECTION_RESPONSE_INVALID1))
    return response


def mocked_validate_invalid2(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(INTROSPECTION_RESPONSE_INVALID2))
    return response


def mocked_validate_invalid3(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(INTROSPECTION_RESPONSE_INVALID3))
    return response


class IntrospectApiClientTest(unittest.TestCase):
    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_ok)
    def test_validate_access_token_valid_with_enricher(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        validation_data = under_test.validate_access_token(TEST_ACCESS_TOKEN, noop_auth_enricher)
        self.assertEqual(INTROSPECTION_RESPONSE_VALID, validation_data)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_ok)
    def test_validate_access_token_valid(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        validation_data = under_test.validate_access_token(TEST_ACCESS_TOKEN, None)
        self.assertEqual(INTROSPECTION_RESPONSE_VALID, validation_data)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_fail)
    def test_validate_access_token_expired(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        with self.assertRaises(IntrospectionRejectionTokenException):
            under_test.validate_access_token(TEST_ACCESS_TOKEN, None)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_invalid1)
    def test_validate_access_token_invalid_response1(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        with self.assertRaises(IntrospectionApiException):
            under_test.validate_access_token(TEST_ACCESS_TOKEN, None)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_invalid2)
    def test_validate_access_token_invalid_response2(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        with self.assertRaises(IntrospectionApiException):
            under_test.validate_access_token(TEST_ACCESS_TOKEN, None)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_invalid3)
    def test_validate_access_token_invalid_response3(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        with self.assertRaises(IntrospectionApiException):
            under_test.validate_access_token(TEST_ACCESS_TOKEN, None)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_ok)
    def test_validate_id_token(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        validation_data = under_test.validate_id_token(TEST_ID_TOKEN, None)
        self.assertEqual(INTROSPECTION_RESPONSE_VALID, validation_data)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_validate_ok)
    def test_validate_refresh_token(self, mock_post):
        under_test = IntrospectionApiClient(introspect_uri=TEST_API_ENDPOINT)
        validation_data = under_test.validate_refresh_token(TEST_REFRESH_TOKEN, None)
        self.assertEqual(INTROSPECTION_RESPONSE_VALID, validation_data)
