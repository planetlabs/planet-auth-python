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

import copy
import json
from abc import ABC, abstractmethod

import jwt.utils
import pathlib
import secrets
from typing import List, Optional, Union

import jwt
import time
import uuid

from planet_auth.storage_utils import (
    FileBackedJsonObjectException,
    ObjectStorageProvider_KeyType,
    ObjectStorageProvider,
)
from planet_auth.credential import Credential
from planet_auth.request_authenticator import CredentialRequestAuthenticator, ForbiddenRequestAuthenticator
from planet_auth.oidc.api_clients.api_client import EnricherPayloadType, EnricherReturnType
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.api_clients.jwks_api_client import JwksApiClient
from planet_auth.oidc.api_clients.token_api_client import TokenApiException
from planet_auth.oidc.auth_client import OidcAuthClientConfig, OidcAuthClient

from tests.test_planet_auth.util import load_rsa_private_key, tdata_resource_file_path

_SCOPE_CLAIM_RFC8693 = "scope"  # See RFC 8693, 9068
_SCOPE_CLAIM_OKTA = "scp"  # Okta uses a different claim


class UtilTokenBuilderBase(ABC):
    """
    Build tokens locally for testing purposes.
    """

    @abstractmethod
    def encode(self, body, extra_headers):
        pass

    def __init__(self, issuer, audience, signing_key_id=None):
        self.signing_key_id = signing_key_id
        self.issuer = issuer
        self.audience = audience

    def _construct_oidc_access_token(self, username: str, ttl: int, extra_claims, remove_claims):
        # Build a fake JWT access token.  For test purposes, it doesn't matter
        # that it cannot be used anywhere.  While some fields are generic and standard
        # the full details of an access token are specific to the authorization
        # server and the application.
        now = int(time.time())
        unsigned_jwt = {
            "iss": self.issuer,
            "sub": username,
            "aud": self.audience,
            "iat": now,
            "exp": now + ttl,
            "jti": str(uuid.uuid4()),
        }
        unsigned_jwt.update(extra_claims)
        if remove_claims:
            for remove_claim in remove_claims:
                if remove_claim in unsigned_jwt:
                    unsigned_jwt.pop(remove_claim)

        headers = {}
        if self.signing_key_id:
            headers["kid"] = self.signing_key_id

        signed_jwt = self.encode(unsigned_jwt, extra_headers=headers)
        return signed_jwt

    def construct_oidc_access_token_okta(
        self, username: str, requested_scopes: list, ttl: int, extra_claims=None, remove_claims=None
    ):
        scope_claims = {"scp": requested_scopes}  # Claim used by Okta for granted scopes.
        if extra_claims:
            extra_claims.update(scope_claims)
        else:
            extra_claims = scope_claims
        return self._construct_oidc_access_token(
            username=username, ttl=ttl, extra_claims=extra_claims, remove_claims=remove_claims
        )

    def construct_oidc_access_token_rfc8693(
        self, username: str, requested_scopes: list, ttl: int, extra_claims=None, remove_claims=None
    ):
        scope_claims = {"scope": " ".join(requested_scopes)}  # RFC 8693 claim used for granted scopes
        if extra_claims:
            extra_claims.update(scope_claims)
        else:
            extra_claims = scope_claims
        return self._construct_oidc_access_token(
            username=username, ttl=ttl, extra_claims=extra_claims, remove_claims=remove_claims
        )

    def construct_oidc_id_token(self, client_id: str, ttl: int, extra_claims=None, remove_claims=None):
        # Build a fake JWT ID token.  For test purposes, it doesn't matter
        # that it cannot be used anywhere.
        now = int(time.time())
        unsigned_jwt = {
            "iss": self.issuer,
            "sub": client_id,
            "aud": client_id,
            "iat": now,
            "exp": now + ttl,
            "jti": str(uuid.uuid4()),
        }
        if extra_claims:
            # Note: this is clobbering of the claims above!  might be fine
            # for this test class, but be warned if you copy-paste somewhere.
            unsigned_jwt.update(extra_claims)

        headers = {}
        if self.signing_key_id:
            headers["kid"] = self.signing_key_id

        if remove_claims:
            for remove_claim in remove_claims:
                if remove_claim in unsigned_jwt:
                    unsigned_jwt.pop(remove_claim)

        signed_jwt = self.encode(body=unsigned_jwt, extra_headers=headers)
        return signed_jwt

    def generate_legacy_token(self, ttl, api_key):
        now = int(time.time())

        unsigned_jwt = {
            "program_id": 7,
            "token_type": "auth",
            "role_level": 9999,
            "organization_id": 99,
            "user_id": 999999,
            "plan_template_id": None,
            "membership_id": 123456,
            "organization_name": "Planet",
            "2fa": False,
            "exp": now + ttl,
            "user_name": "Test User",
            "email": "test.user@planet.com",
        }
        if api_key:
            unsigned_jwt["api_key"] = api_key

        signed_jwt = self.encode(body=unsigned_jwt, extra_headers=None)
        return signed_jwt


class TestTokenBuilder(UtilTokenBuilderBase):
    """
    Build tokens locally for testing purposes.
    """

    def __init__(self, signing_key_file, signing_key_algorithm="RS256", **kwargs):
        super().__init__(**kwargs)
        self.signing_key_file = signing_key_file
        self.signing_key = load_rsa_private_key(signing_key_file)
        self.signing_key_algorithm = signing_key_algorithm

    def encode(self, body, extra_headers):
        return jwt.encode(body, self.signing_key, algorithm=self.signing_key_algorithm, headers=extra_headers)

    @staticmethod
    def test_token_builder_factory(keypair_name):
        public_key_file = tdata_resource_file_path("keys/{}_pub_jwk.json".format(keypair_name))
        signing_key_file = tdata_resource_file_path("keys/{}_priv_nopassword.test_pem".format(keypair_name))

        with open(public_key_file, "r", encoding="UTF-8") as file_r:
            pubkey_data = json.load(file_r)

        signing_key_id = pubkey_data["kid"]
        signing_key_algorithm = pubkey_data["alg"]
        token_builder = TestTokenBuilder(
            issuer="test_token_issuer_for_" + keypair_name,
            audience="test_token_audience_for_" + keypair_name,
            signing_key_file=signing_key_file,
            signing_key_id=signing_key_id,
            signing_key_algorithm=signing_key_algorithm,
        )
        return pubkey_data, token_builder


class FakeTokenBuilder(UtilTokenBuilderBase):
    """
    Build fake tokens that have complete random garbage as the signature and lie about the signing algorithm.
    """

    def __init__(self, signing_key_algorithm="RS256", **kwargs):
        super().__init__(**kwargs)
        self.signing_key_algorithm = signing_key_algorithm

    @staticmethod
    def fake_token(header, body):
        return "{}.{}.{}".format(
            str(
                jwt.utils.base64url_encode(
                    bytes(
                        json.dumps(header),
                        "utf-8",
                    )
                ),
                encoding="utf-8",
            ),
            str(
                jwt.utils.base64url_encode(bytes(json.dumps(body), "utf-8")),
                encoding="utf-8",
            ),
            str(jwt.utils.base64url_encode(secrets.token_bytes(256)), encoding="utf-8"),
        )

    def encode(self, body, extra_headers):
        headers = {"alg": self.signing_key_algorithm}
        if extra_headers:
            headers.update(extra_headers)
        return self.fake_token(body=body, header=headers)


class StubOidcClientConfig(OidcAuthClientConfig):
    def __init__(
        self,
        stub_authority_ttl,
        stub_authority_access_token_audience,
        stub_authority_signing_key_file,
        stub_authority_pub_key_file,
        **kwargs,
    ):
        # A primary goal in this patching of the super class is to prevent
        # network reach out.  In many cases, we are shorting out OIDC discovery.
        if not "client_id" in kwargs:
            kwargs["client_id"] = "__stub_client_id__"

        kwargs["jwks_endpoint"] = "__stub_jwks_endpoint__"
        kwargs["issuer"] = kwargs["auth_server"]

        super().__init__(**kwargs)
        self.stub_authority_ttl = stub_authority_ttl
        self.stub_authority_access_token_audience = stub_authority_access_token_audience
        self.stub_authority_token_signing_key_file = stub_authority_signing_key_file
        self.stub_authority_pub_key_file = stub_authority_pub_key_file


class StubJwksApiClient(JwksApiClient):
    def __init__(self, jwks_uri, pubkey_file):
        super().__init__(jwks_uri=jwks_uri)
        self._keys = []
        with open(pubkey_file, "r", encoding="UTF-8") as file_r:
            pubkey_data = json.load(file_r)
            if "keys" in pubkey_data:
                for key in pubkey_data["keys"]:
                    self._keys.append(key)
            else:
                self._keys.append(pubkey_data)

    def _checked_fetch(self):
        return {"keys": self._keys}


class StubOidcAuthClient(OidcAuthClient):
    """
    A stub auth client that implements a token issuing authority that is entirely local.
    This can be used to mock out the OidcAuthClient in unit tests that are testing
    functionality that is built on top of the auth client.
    """

    def __init__(self, client_config: StubOidcClientConfig):
        super().__init__(client_config)
        self._mock_client_config = client_config
        self._refresh_state = {}

        # Monkey patch jwks to match our stub token issuer.
        # This looks so wrong. There has to be a better way to patch superclass variables?
        jwks_client = StubJwksApiClient(
            self._mock_client_config.jwks_endpoint(), pubkey_file=self._mock_client_config.stub_authority_pub_key_file
        )
        self._OidcAuthClient__jwks_client = jwks_client
        self.token_builder = TestTokenBuilder(
            issuer=self._mock_client_config.auth_server(),
            audience=self._mock_client_config.stub_authority_access_token_audience,
            signing_key_file=self._mock_client_config.stub_authority_token_signing_key_file,
            signing_key_id=jwks_client._keys[0]["kid"],
        )

    def _construct_oidc_credential(
        self,
        get_access_token: bool,
        get_id_token: bool,
        get_refresh_token: bool,
        username: str,
        requested_scopes: list,
        extra_claims,
        remove_claims,
    ):
        jwt_access_token = self.token_builder.construct_oidc_access_token_rfc8693(
            username=username,
            requested_scopes=requested_scopes,
            ttl=self._mock_client_config.stub_authority_ttl,
            extra_claims=extra_claims,
            remove_claims=remove_claims,
        )
        jwt_id_token = self.token_builder.construct_oidc_id_token(
            client_id=self._mock_client_config.client_id(),
            ttl=self._mock_client_config.stub_authority_ttl,
            extra_claims=extra_claims,
            remove_claims=remove_claims,
        )

        credential_data = {
            "token_type": "Bearer",
            "expires_in": self._mock_client_config.stub_authority_ttl,
            "scope": " ".join(requested_scopes),
        }
        if get_access_token:
            credential_data["access_token"] = jwt_access_token
        if get_id_token:
            credential_data["id_token"] = jwt_id_token
        if get_refresh_token:
            refresh_token = str(uuid.uuid4())
            credential_data["refresh_token"] = refresh_token
            self._refresh_state[refresh_token] = {
                "get_id_token": get_id_token,
                "get_access_token": get_access_token,
                "username": username,
                "extra_claims": extra_claims,
                "requested_scopes": requested_scopes,
            }

        credential = FileBackedOidcCredential(data=credential_data)
        return credential

    def _client_auth_enricher(self, raw_payload: EnricherPayloadType, audience: str) -> EnricherReturnType:
        # return raw_payload, None
        # Abstract in the base class. Not under test here.
        assert 0

    def _oidc_flow_login(
        self,
        allow_open_browser=False,
        allow_tty_prompt=False,
        requested_scopes=None,
        requested_audiences=None,
        extra=None,
        username=None,
        get_access_token=True,
        get_id_token=True,
        get_refresh_token=True,
        extra_claims=None,
        remove_claims=None,
        **kwargs,
    ) -> FileBackedOidcCredential:
        if not requested_scopes:
            requested_scopes = self._mock_client_config.scopes()
        return self._construct_oidc_credential(
            get_access_token=get_access_token,
            get_id_token=get_id_token,
            get_refresh_token=get_refresh_token,
            username=username,
            requested_scopes=requested_scopes,
            extra_claims=extra_claims,
            remove_claims=remove_claims,
        )

    def refresh(
        self, refresh_token: str, requested_scopes: List[str] = None, extra: Optional[dict] = None
    ) -> FileBackedOidcCredential:
        # FIXME?  This is a test stub implementation. We ignore requests
        #         to change scopes on refresh.
        if refresh_token:
            return self._construct_oidc_credential(
                get_refresh_token=True,
                get_access_token=self._refresh_state[refresh_token]["get_access_token"],
                get_id_token=self._refresh_state[refresh_token]["get_id_token"],
                username=self._refresh_state[refresh_token]["username"],
                requested_scopes=self._refresh_state[refresh_token]["requested_scopes"],
                extra_claims=self._refresh_state[refresh_token]["extra_claims"],
                remove_claims=None,
            )
        else:
            # raise AuthClientException("cannot refresh without refresh token")
            raise TokenApiException(message="cannot refresh without refresh token")

    def validate_access_token_remote(self, access_token: str) -> dict:
        # Stubbing out remote network calls.  Our "remote" validator will
        # do a local validation, then construct a matching RFC 7662 response
        local_validation = self.validate_access_token_local(
            access_token=access_token, required_audience=self._mock_client_config.stub_authority_access_token_audience
        )
        if not local_validation:  # Local validation should throw if invalid, but just in case...
            return {"active": False}

        if local_validation.get(_SCOPE_CLAIM_RFC8693):
            # RFC 8693 places scopes in a space delimited string.
            token_scopes = local_validation.get(_SCOPE_CLAIM_RFC8693).split()
        elif local_validation.get(_SCOPE_CLAIM_OKTA):
            # No split.  Okta places a list of strings in the token.
            token_scopes = local_validation.get(_SCOPE_CLAIM_OKTA)
        else:
            token_scopes = []

        return {
            "active": True,
            "iss": local_validation.get("iss"),
            "aud": local_validation.get("aud"),
            "sub": local_validation.get("sub"),
            "scope": " ".join(token_scopes),
            "exp": local_validation.get("exp"),
            "iat": local_validation.get("iat"),
            "jti": local_validation.get("jti"),
        }

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> CredentialRequestAuthenticator:
        # Abstract in the base class. Not under test here.
        return ForbiddenRequestAuthenticator()

    def can_login_unattended(self) -> bool:
        return True


class MockStorageObjectNotFound(FileBackedJsonObjectException):
    pass


class MockObjectStorageProvider(ObjectStorageProvider):
    def __init__(self, initial_mock_storage):
        self._mock_storage = copy.deepcopy(initial_mock_storage)

    def _peek(self):
        return self._mock_storage

    def load_obj(self, key: ObjectStorageProvider_KeyType) -> dict:
        if key not in self._mock_storage:
            raise MockStorageObjectNotFound
        return self._mock_storage[key]

    def save_obj(self, key: ObjectStorageProvider_KeyType, data: dict) -> None:
        self._mock_storage[key] = data

    def obj_exists(self, key: ObjectStorageProvider_KeyType) -> bool:
        return key in self._mock_storage

    def mtime(self, key: ObjectStorageProvider_KeyType) -> float:
        # Fake storage provider.  We don't know when objects were last modified.
        return 0.0

    def obj_rename(self, src: ObjectStorageProvider_KeyType, dst: ObjectStorageProvider_KeyType) -> None:
        if self._mock_storage[src] is not None:
            self._mock_storage[dst] = self._mock_storage[src]
            del self._mock_storage[src]
        else:
            del self._mock_storage[dst]
