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

"""
Some OIDC endpoints require client auth, and how auth is done can very
depending on how the OIDC provider is configured to handle the particular
client. See
https://developer.okta.com/docs/reference/api/oidc/#client-authentication-methods

This module provides some helper functions for wrangling the requests for
various OIDC client auth methods.  It is for the caller to decide the
appropriate use of these.
"""

import jwt
import time
import uuid

from typing import Dict
from requests.auth import HTTPBasicAuth

from planet_auth.oidc.api_clients.api_client import _RequestAuthType, _RequestParamsType


def _prepare_oidc_client_jwt_payload(audience: str, client_id: str, ttl: int):
    # See
    # https://developer.okta.com/docs/reference/api/oidc/#token-claims-for-client-authentication-with-client-secret-or-private-key-jwt
    # https://datatracker.ietf.org/doc/html/rfc7523
    now = int(time.time())
    unsigned_jwt = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    return unsigned_jwt


def prepare_oidc_client_private_key_jwt(audience: str, client_id: str, private_key, ttl: int):
    unsigned_jwt = _prepare_oidc_client_jwt_payload(audience=audience, client_id=client_id, ttl=ttl)
    signed_jwt = jwt.encode(unsigned_jwt, private_key, algorithm="RS256")
    return signed_jwt


def prepare_client_noauth_auth_payload(client_id: str) -> Dict:
    client_secret_auth_payload = {
        "client_id": client_id,
    }
    return client_secret_auth_payload


def prepare_client_secret_request_auth(client_id: str, client_secret: str) -> _RequestAuthType:
    return HTTPBasicAuth(client_id, client_secret)


def prepare_client_secret_auth_payload(client_id: str, client_secret: str) -> _RequestParamsType:
    client_secret_auth_payload = {"client_id": client_id, "client_secret": client_secret}
    return client_secret_auth_payload


def prepare_private_key_assertion_auth_payload(
    audience: str, client_id: str, private_key, ttl: int
) -> _RequestParamsType:
    signed_jwt = prepare_oidc_client_private_key_jwt(
        audience=audience, client_id=client_id, private_key=private_key, ttl=ttl
    )
    assertion_auth_payload = {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": signed_jwt,
    }
    return assertion_auth_payload
