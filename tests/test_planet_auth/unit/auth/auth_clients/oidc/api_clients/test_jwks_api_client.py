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
from unittest import mock

from planet_auth.oidc.api_clients.jwks_api_client import JwksApiClient, JwksApiException

TEST_API_ENDPOINT = "https://blackhole.unittest.planet.com/api"
# Random snapshot of public keys from one of our Okta instances. We are
# not verifying keys in this test, so it doesn't matter that we can't generate
# tokens with these signers.
API_RESPONSE_VALID = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "kid": "WtxCYJa7oQqkLTwJYTfSeB1ZxUcY9h4tF7NL26Px1Tg",
            "use": "sig",
            "e": "AQAB",
            "n": "laSDEVkNhVp7XIvj6YYLELWstWefAR8it12K-qTDVsHCRDfOoPh97Yv0A3cVH6QPM_IoVTJ224yIQgpdTUykk3IN7Yem9WaZ0FC5AxjXWpBHDZpP5ZAjpBsR_r66pB2l_wDSDXZlN_k4VR4rbTjiGGsLqgY9J2QDLPyr5dormrO7E0inPuwLor2KTJkafSZd6AjifUkYS6zJQLvXenmD_7QTRVnYX2R07lzwctykVAj6ppM9KwQcqiSy9x-HqHm2wikQ1KzqBmXdCMLXB-FCFV4SbmC94744Rmhdb85bonX7TjZfvrurzBpO9ZhpSOeYXIDBwuJA4bsYYw-o6PYZaw",
        },
        {
            "kty": "RSA",
            "alg": "RS256",
            "kid": "S8fLvVhqvvxLxiwBdT7FXfIPGkV-I6LuRCwsaUsFqB4",
            "use": "sig",
            "e": "AQAB",
            "n": "l7Zho6s9npWRBX0590Vum9y4H5IIY2oTG-bJfw6OEIsMLDK8NW9jcFtFGsB7vuUvnPwiK9drI_ekApDZ8byfpIzBkJ9CIz3CU2xNZIaOEH8oU2Ywoviov6VBMDoSnoURGr57AYDnnuWsihgiZaH58ghmitbF_n9PPxhR62OP6M_fk8Dr7tDbtt4_mtVziLH8zDw0SrGFZZLhFmfmIGzoXxInnCpBCa6iVwqDjypB499-H2uIYyqiNoc-sR-CNUUFiRFZxZZeZDxkRm_M_gGVVbqCMgtzr8Y2z37hn2ZO1ylZc9TfOw2DY2dy4h7CKfjbhlAYn0Ckp6vxbopVhagY4Q",
        },
    ]
}
# API_RESPONSE_EMPTY_KEYSET = {"keys": []}
API_RESPONSE_INVALID_RESPONSE = {"bad": "payload"}


def mocked_response_ok(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_VALID))
    return response


# def mocked_response_empty(request_url, **kwargs):
#    response = Response()
#    response.status_code = 200
#    response.headers['content-type'] = 'application/json'
#    response._content = str.encode(json.dumps(API_RESPONSE_EMPTY_KEYSET))
#    return response


def mocked_response_invalid(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_INVALID_RESPONSE))
    return response


class JWKSApiClientTest(unittest.TestCase):
    @mock.patch("requests.sessions.Session.get", side_effect=mocked_response_ok)
    def test_fetch_keys_valid(self, mock_get):
        under_test = JwksApiClient(jwks_uri=TEST_API_ENDPOINT)
        keys = under_test.jwks_keys()
        self.assertEqual(API_RESPONSE_VALID["keys"], keys)

    @mock.patch("requests.sessions.Session.get", side_effect=mocked_response_invalid)
    def test_invalid(self, mock_get):
        under_test = JwksApiClient(jwks_uri=TEST_API_ENDPOINT)
        with self.assertRaises(JwksApiException):
            under_test.jwks_keys()
