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

from planet_auth.oidc.api_clients.revocation_api_client import RevocationApiClient

TEST_API_ENDPOINT = "https://blackhole.unittest.planet.com/api"
TEST_ACCESS_TOKEN = "__test_access_token__"
TEST_REFRESH_TOKEN = "__test_refresh_token__"
API_RESPONSE_VALID = {}
API_RESPONSE_FAILED = {}


def noop_auth_enricher(raw_payload: dict, audience: str) -> Tuple[dict, Optional[AuthBase]]:
    return raw_payload, None


def mocked_response_ok(request_url, **kwargs):
    response = Response()
    response.status_code = 200
    response.headers["content-type"] = "application/json"
    response._content = str.encode(json.dumps(API_RESPONSE_VALID))
    return response


class RevocationApiClientTest(unittest.TestCase):
    """
    Revocation API testing is very boring.  By design, the endpoint doesn't
    tell you much. All of our expected error handling is tested with the base
    class.
    """

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_revoke_access_token_with_enricher(self, mock_post):
        under_test = RevocationApiClient(revocation_uri=TEST_API_ENDPOINT)
        under_test.revoke_access_token(TEST_ACCESS_TOKEN, noop_auth_enricher)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_revoke_access_token_without_enricher(self, mock_post):
        under_test = RevocationApiClient(revocation_uri=TEST_API_ENDPOINT)
        under_test.revoke_access_token(TEST_ACCESS_TOKEN, None)

    @mock.patch("requests.sessions.Session.post", side_effect=mocked_response_ok)
    def test_revoke_refresh_token(self, mock_post):
        under_test = RevocationApiClient(revocation_uri=TEST_API_ENDPOINT)
        under_test.revoke_refresh_token(TEST_REFRESH_TOKEN, None)
