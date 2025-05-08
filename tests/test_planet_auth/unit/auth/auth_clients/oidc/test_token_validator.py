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
import jwt.utils
import secrets
import freezegun
import unittest
from unittest.mock import MagicMock

from planet_auth.oidc.api_clients.jwks_api_client import JwksApiClient
from planet_auth import (
    TokenValidator,
    InvalidArgumentException,
    InvalidTokenException,
    ExpiredTokenException,
    ScopeNotGrantedTokenException,
    InvalidAlgorithmTokenException,
)
from planet_auth.oidc.token_validator import UnknownSigningKeyTokenException
from tests.test_planet_auth.unit.auth.util import TestTokenBuilder, FakeTokenBuilder
from tests.test_planet_auth.util import tdata_resource_file_path

TEST_JWKS_ENDPOINT = "https://blackhole.unittest.planet.com/oauth/jwks"
TEST_TOKEN_TTL = 60
TEST_TOKEN_USER = "unit_test_user"
TEST_TOKEN_SCOPE_1 = "test_unit_test_scope1"
TEST_TOKEN_SCOPE_2 = "test_unit_test_scope2"
TEST_TOKEN_SCOPE_3 = "test_unit_test_scope3"
TEST_TOKEN_SCOPES = [TEST_TOKEN_SCOPE_1, TEST_TOKEN_SCOPE_2]


class TestTokenValidator(unittest.TestCase):
    token_builder_1 = None
    token_builder_2 = None
    token_builder_3 = None
    token_builder_4 = None
    mock_jwks_response = None
    MIN_JWKS_FETCH_INTERVAL = 8

    @staticmethod
    def initialize_token_builder(keypair_name):
        return TestTokenBuilder.test_token_builder_factory(keypair_name=keypair_name)

    @staticmethod
    def initialize_fake_token_builder(keypair_name):
        public_key_file = tdata_resource_file_path("keys/{}_pub_jwk.json".format(keypair_name))

        with open(public_key_file, "r", encoding="UTF-8") as file_r:
            pubkey_data = json.load(file_r)

        signing_key_id = pubkey_data["kid"]
        signing_key_algorithm = pubkey_data["alg"]
        token_builder = FakeTokenBuilder(
            issuer="test_token_issuer_for_" + keypair_name,
            audience="test_token_audience_for_" + keypair_name,
            signing_key_id=signing_key_id,
            signing_key_algorithm=signing_key_algorithm,
        )
        return pubkey_data, token_builder

    @classmethod
    def setUpClass(cls):
        # key 2 is unknown to our mock jwks endpoint
        # key 4 is an algorithm we expect to be unsupported by the python runtime, regardless of
        #     configuration. Updates to python libs could change that, and break test assumptions.
        #     The thing about a test for a signing key algorithm not implemented by the libraries
        #     we are built on...  We can't generate a valid token. Use a fake token builder.
        pubkey_jwk_1, token_builder_1 = cls.initialize_token_builder("keypair1")  # Uses a RS256 keypair
        pubkey_jwk_2, token_builder_2 = cls.initialize_token_builder("keypair2")  # Uses a RS256 keypair
        pubkey_jwk_3, token_builder_3 = cls.initialize_token_builder("keypair3")  # Uses a RS512 keypair
        pubkey_jwk_4, token_builder_4 = cls.initialize_fake_token_builder("keypair4")  # Specifies RSA-OAEP Algorithm

        cls.token_builder_1 = token_builder_1
        cls.token_builder_2 = token_builder_2
        cls.token_builder_3 = token_builder_3
        cls.token_builder_4 = token_builder_4

        cls.mock_jwks_response = {"keys": [pubkey_jwk_1, pubkey_jwk_3, pubkey_jwk_4]}

    def setUp(self):
        mock_jwks_client = JwksApiClient(jwks_uri=TEST_JWKS_ENDPOINT)
        mock_jwks_client.jwks = MagicMock(return_value=self.mock_jwks_response)
        self.under_test_1 = TokenValidator(jwks_client=mock_jwks_client)
        self.under_test_2 = TokenValidator(
            jwks_client=mock_jwks_client, min_jwks_fetch_interval=self.MIN_JWKS_FETCH_INTERVAL
        )
        self.under_test_3 = TokenValidator(jwks_client=mock_jwks_client, trusted_algorithms=["RSA", "RSA-OAEP"])

    def test_valid_access_token(self):
        # QE TC0, TC1
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        validated_claims = under_test.validate_token(
            access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
        )
        self.assertEqual(TEST_TOKEN_USER, validated_claims["sub"])

    def test_empty_access_token(self):
        # QE TC3, TC5
        under_test = self.under_test_1
        with self.assertRaises(InvalidArgumentException):
            under_test.validate_token(
                "",
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )
        with self.assertRaises(InvalidArgumentException):
            under_test.validate_token(
                None,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_malformed_token_1(self):
        # QE TC6 - just some random garbage.
        under_test = self.under_test_1
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=secrets.token_bytes(2048),
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_malformed_token_2(self):
        # QE TC6 - just some random garbage, but URL safe.
        under_test = self.under_test_1
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=secrets.token_urlsafe(2048),
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_malformed_token_3(self):
        # QE TC6 - random garbage, but has JWT three dot structure.
        under_test = self.under_test_1
        fake_jwt = "{}.{}.{}".format(
            str(jwt.utils.base64url_encode(secrets.token_bytes(256)), encoding="utf-8"),
            str(jwt.utils.base64url_encode(secrets.token_bytes(2048)), encoding="utf-8"),
            str(jwt.utils.base64url_encode(secrets.token_bytes(256)), encoding="utf-8"),
        )

        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=fake_jwt,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_malformed_token_4(self):
        # QE TC6 - random garbage, but looks more JWT like with encoded json.
        def _fake_token(header, body):
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

        under_test = self.under_test_1
        fake_jwt = _fake_token(
            {
                "alg": self.token_builder_1.signing_key_algorithm,
                "kid": self.token_builder_1.signing_key_id,
            },
            {"fake_claim": "test claim value"},
        )

        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=fake_jwt,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_malformed_token_missing_issuer(self):
        # QE TC14
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL, remove_claims=["iss"]
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_altered_token(self):
        # QE TC10
        def _alter_token(access_token, old_claim_value, new_claim_value):
            # Byte rather than string or object based alteration to keep the changes that may impact signature
            # generation to a minimum (ordering, spacing, length, encoding, etc.)
            old_header_b64str, old_body_b64str, old_sig_b64str = access_token.split(".")
            old_body_bytes = jwt.utils.base64url_decode(old_body_b64str)
            new_body_bytes = old_body_bytes.replace(
                bytes(old_claim_value, encoding="utf-8"), bytes(new_claim_value, encoding="utf-8"), 1
            )
            new_body_b64str = str(jwt.utils.base64url_encode(new_body_bytes), encoding="utf-8")
            altered_token = "{}.{}.{}".format(old_header_b64str, new_body_b64str, old_sig_b64str)
            return altered_token

        under_test = self.under_test_1

        # run the test without altering our token first.
        # This is to test the test, to make sure we are only altering what we think we are altering.
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER,
            requested_scopes=TEST_TOKEN_SCOPES,
            ttl=TEST_TOKEN_TTL,
            extra_claims={"test_sensitive_claim": "sensitive_value_A"},
        )
        altered_access_token = _alter_token(access_token, "sensitive_value_A", "sensitive_value_A")
        under_test.validate_token(
            altered_access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
        )

        # Now, actually change the claim value, and look for the exception
        altered_access_token = _alter_token(access_token, "sensitive_value_A", "sensitive_value_B")
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                altered_access_token,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_missing_signature_1(self):
        # QE TC11 - JWT without a signature, but with the "."
        def _bad_token(header, body):
            return "{}.{}.".format(
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
            )

        under_test = self.under_test_1
        bad_jwt = _bad_token(
            {
                "alg": self.token_builder_1.signing_key_algorithm,
                "kid": self.token_builder_1.signing_key_id,
            },
            {"fake_claim": "test claim value"},
        )

        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=bad_jwt,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_missing_signature_2(self):
        # QE TC11 - JWT without a signature, and with no second "."
        def _bad_token(header, body):
            return "{}.{}".format(
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
            )

        under_test = self.under_test_1
        bad_jwt = _bad_token(
            {
                "alg": self.token_builder_1.signing_key_algorithm,
                "kid": self.token_builder_1.signing_key_id,
            },
            {"fake_claim": "test claim value"},
        )

        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=bad_jwt,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_empty_issuer_arg(self):
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        validated_claims = under_test.validate_token(
            access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
        )
        self.assertEqual(TEST_TOKEN_USER, validated_claims["sub"])
        with self.assertRaises(InvalidArgumentException):
            validated_claims = under_test.validate_token(
                access_token,
                issuer="",
                audience=self.token_builder_1.audience,
            )
        with self.assertRaises(InvalidArgumentException):
            validated_claims = under_test.validate_token(
                access_token,
                issuer=None,
                audience=self.token_builder_1.audience,
            )

    def test_empty_audience_arg(self):
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        validated_claims = under_test.validate_token(
            access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
        )
        self.assertEqual(TEST_TOKEN_USER, validated_claims["sub"])
        with self.assertRaises(InvalidArgumentException):
            validated_claims = under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience="",
            )
        with self.assertRaises(InvalidArgumentException):
            validated_claims = under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience=None,
            )

    def test_access_token_unknown_signing_key(self):
        # QE TC12
        under_test = self.under_test_1
        access_token = self.token_builder_2.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(UnknownSigningKeyTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_2.issuer,
                audience=self.token_builder_2.audience,
            )

    def test_access_token_issuer_mismatch(self):
        # QE TC15 untrusted issuer. (See also multi-validator tests)
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer + "_make_it_mismatch",
                audience=self.token_builder_1.audience,
            )

    def test_access_token_incorrect_audience(self):
        # QE TC17
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience + "_make_it_mismatch",
            )

    def test_access_token_multiple_audiences(self):
        # QE TC17
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER,
            requested_scopes=TEST_TOKEN_SCOPES,
            ttl=TEST_TOKEN_TTL,
            extra_claims={"aud": [self.token_builder_1.audience, "extra_audience_1", "extra_audience_2"]},
        )
        under_test.validate_token(
            token_str=access_token, issuer=self.token_builder_1.issuer, audience=self.token_builder_1.audience
        )
        under_test.validate_token(
            token_str=access_token, issuer=self.token_builder_1.issuer, audience="extra_audience_1"
        )
        under_test.validate_token(
            token_str=access_token, issuer=self.token_builder_1.issuer, audience="extra_audience_2"
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_str=access_token, issuer=self.token_builder_1.issuer, audience="extra_audience_3"
            )

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_access_token_expired(self, frozen_time):
        # QE TC2
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=3
        )
        frozen_time.tick(5)
        with self.assertRaises(ExpiredTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

    def test_access_token_missing_claim(self):
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
                required_claims=["missing_claim_1", "missing_claim_2"],
            )

    def test_access_token_scope_validation__no_scopes_required__rfc8692(self):
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=[], ttl=TEST_TOKEN_TTL
        )
        under_test.validate_token(
            access_token, issuer=self.token_builder_1.issuer, audience=self.token_builder_1.audience, scopes_anyof=None
        )

        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        under_test.validate_token(
            access_token, issuer=self.token_builder_1.issuer, audience=self.token_builder_1.audience, scopes_anyof=None
        )

    def test_access_token_scope_validation__no_scopes_required__okta(self):
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_okta(
            username=TEST_TOKEN_USER, requested_scopes=[], ttl=TEST_TOKEN_TTL
        )
        under_test.validate_token(
            access_token, issuer=self.token_builder_1.issuer, audience=self.token_builder_1.audience, scopes_anyof=None
        )

        access_token = self.token_builder_1.construct_oidc_access_token_okta(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        under_test.validate_token(
            access_token, issuer=self.token_builder_1.issuer, audience=self.token_builder_1.audience, scopes_anyof=None
        )

    def _scope_validation_assertions(self, under_test, access_token):
        under_test.validate_token(
            access_token, issuer=self.token_builder_1.issuer, audience=self.token_builder_1.audience, scopes_anyof=None
        )
        under_test.validate_token(
            access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
            scopes_anyof=[TEST_TOKEN_SCOPE_1],
        )
        under_test.validate_token(
            access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
            scopes_anyof=[TEST_TOKEN_SCOPE_2],
        )
        under_test.validate_token(
            access_token,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
            scopes_anyof=[TEST_TOKEN_SCOPE_1, TEST_TOKEN_SCOPE_2],
        )
        with self.assertRaises(ScopeNotGrantedTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
                scopes_anyof=[TEST_TOKEN_SCOPE_3],
            )

    def test_access_token_scope_validation__scope_required__rfc8693(self):
        # QE TC16
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=[TEST_TOKEN_SCOPE_1, TEST_TOKEN_SCOPE_2], ttl=TEST_TOKEN_TTL
        )
        self._scope_validation_assertions(under_test, access_token)

        access_token = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=[], ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(InvalidTokenException):
            self._scope_validation_assertions(under_test, access_token)

    def test_access_token_scope_validation__scope_required__okta(self):
        # QE TC16
        under_test = self.under_test_1
        access_token = self.token_builder_1.construct_oidc_access_token_okta(
            username=TEST_TOKEN_USER, requested_scopes=[TEST_TOKEN_SCOPE_2, TEST_TOKEN_SCOPE_1], ttl=TEST_TOKEN_TTL
        )
        self._scope_validation_assertions(under_test, access_token)

        access_token = self.token_builder_1.construct_oidc_access_token_okta(
            username=TEST_TOKEN_USER, requested_scopes=[], ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(InvalidTokenException):
            self._scope_validation_assertions(under_test, access_token)

    def test_id_token_nonce(self):
        under_test = self.under_test_1
        id_token_with_nonce = self.token_builder_1.construct_oidc_id_token(
            ttl=TEST_TOKEN_TTL, client_id="test_client_id", extra_claims={"nonce": "12345"}
        )
        id_token_without_nonce = self.token_builder_1.construct_oidc_id_token(
            ttl=TEST_TOKEN_TTL, client_id="test_client_id"
        )

        under_test.validate_id_token(
            id_token_with_nonce, issuer=self.token_builder_1.issuer, client_id="test_client_id", nonce="12345"
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_id_token(
                id_token_with_nonce, issuer=self.token_builder_1.issuer, client_id="test_client_id", nonce="67890"
            )

        # TODO: See comments in the class.  Unsure if we should make missing
        #  nonce check's fatal when there is a nonce.  It would be very strict.
        under_test.validate_id_token(
            id_token_with_nonce, issuer=self.token_builder_1.issuer, client_id="test_client_id", nonce=None
        )

        with self.assertRaises(InvalidTokenException):
            under_test.validate_id_token(
                id_token_without_nonce,
                issuer=self.token_builder_1.issuer,
                client_id="test_client_id",
                nonce="12345",
            )
        under_test.validate_id_token(
            id_token_with_nonce, issuer=self.token_builder_1.issuer, client_id="test_client_id"
        )

    def test_validate_id_token_multiple_audiences(self):
        under_test = self.under_test_1
        # Happy path, azp contains expected value when multiple
        # audience claims are present
        id_token = self.token_builder_1.construct_oidc_id_token(
            ttl=TEST_TOKEN_TTL,
            client_id="test_client_id",
            extra_claims={"aud": ["test_client_id", "extra_audience_1", "extra_audience_2"], "azp": "test_client_id"},
        )
        validated_claims = under_test.validate_id_token(
            id_token, issuer=self.token_builder_1.issuer, client_id="test_client_id"
        )
        self.assertEqual("test_client_id", validated_claims["sub"])

        # azp claim is missing when multiple audiences are present.
        id_token = self.token_builder_1.construct_oidc_id_token(
            ttl=TEST_TOKEN_TTL,
            client_id="test_client_id",
            extra_claims={"aud": ["test_client_id", "extra_audience_1", "extra_audience_2"]},
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_id_token(id_token, issuer=self.token_builder_1.issuer, client_id="test_client_id")

        # azp claim doesn't contain expected value when multiple audiences
        # are present
        id_token = self.token_builder_1.construct_oidc_id_token(
            ttl=TEST_TOKEN_TTL,
            client_id="test_client_id",
            extra_claims={"aud": ["test_client_id", "extra_audience_1", "extra_audience_2"], "azp": "mismatch_azp"},
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_id_token(id_token, issuer=self.token_builder_1.issuer, client_id="test_client_id")

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_min_jwks_fetch_interval(self, frozen_time):
        under_test = self.under_test_2
        token_known_signer = self.token_builder_1.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        token_unknown_signer = self.token_builder_2.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )

        # t0 - initial state
        self.assertEqual(0, under_test._jwks_client.jwks.call_count)

        # t1 - key miss loads keys
        with self.assertRaises(UnknownSigningKeyTokenException):
            under_test.validate_token(
                token_unknown_signer,
                issuer=self.token_builder_2.issuer,
                audience=self.token_builder_2.audience,
            )
        self.assertEqual(1, under_test._jwks_client.jwks.call_count)

        # t2 - key hit should pull from hot cache.
        under_test.validate_token(
            token_known_signer,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
        )
        self.assertEqual(1, under_test._jwks_client.jwks.call_count)

        # t3 - Repeated key hits and misses inside the fetch interval should
        # not trigger a reload of the jwks verification keys
        for n in range(5):
            with self.assertRaises(InvalidTokenException):
                under_test.validate_token(
                    token_unknown_signer,
                    issuer=self.token_builder_2.issuer,
                    audience=self.token_builder_2.audience,
                )
            under_test.validate_token(
                token_known_signer,
                issuer=self.token_builder_1.issuer,
                audience=self.token_builder_1.audience,
            )

        self.assertEqual(1, under_test._jwks_client.jwks.call_count)

        # t4 - after the interval has passed, a we should reload for any
        # request.  If a miss comes in before the next interval, it should not
        # trigger a reload.  Also, it's not automatic, it's on demand.
        frozen_time.tick(self.MIN_JWKS_FETCH_INTERVAL + 2)
        self.assertEqual(1, under_test._jwks_client.jwks.call_count)
        under_test.validate_token(
            token_known_signer,
            issuer=self.token_builder_1.issuer,
            audience=self.token_builder_1.audience,
        )
        with self.assertRaises(InvalidTokenException):
            under_test.validate_token(
                token_unknown_signer,
                issuer=self.token_builder_2.issuer,
                audience=self.token_builder_2.audience,
            )
        self.assertEqual(2, under_test._jwks_client.jwks.call_count)

    def test_untrusted_token_algorithm(self):
        # QE TC13 - test a token that is using an untrusted algorithm
        under_test = self.under_test_1
        test_token = self.token_builder_3.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(InvalidAlgorithmTokenException):
            under_test.validate_token(
                test_token,
                issuer=self.token_builder_3.issuer,
                audience=self.token_builder_3.audience,
            )

    def test_jwks_endpoint_lists_unsupported_algorithm(self):
        # See CG-867
        # The problem encountered was when the JWKS endpoint listed public
        # keys that were not supported by the underlying Python libraries
        # we depended on.
        #
        # The behavior we have settled on is that seeing such a key in a
        # JWKS response will produce a warning.  Trying to validate a token
        # signed with such a key will still be a fatal token validation
        # error.
        #
        # If your cloud architecture includes OAuth servers using signing
        # keys your resource servers do not support, how much of a problem
        # this is comes down to whether the offending keypairs are used to
        # sign access tokens for the specific resource server/audience.
        # Under normal circumstances, I would expect authorization servers
        # and resource servers to be configured in harmony.
        #
        # This behavior effectively overlaps that of QE TC12. Attempts to
        # validate tokens signed with such a keypair should be treated like
        # attempts to use a token signed with an unknown token

        under_test = self.under_test_3

        # Verify that the token validator did not load the offending key.
        under_test._update()
        self.assertEqual(2, len(under_test._keys_by_id))
        self.assertNotIn(self.token_builder_4.signing_key_id, under_test._keys_by_id)

        # Verify that a token signed with an unsupported key fails
        access_token = self.token_builder_4.construct_oidc_access_token_rfc8693(
            username=TEST_TOKEN_USER, requested_scopes=TEST_TOKEN_SCOPES, ttl=TEST_TOKEN_TTL
        )
        with self.assertRaises(UnknownSigningKeyTokenException):
            under_test.validate_token(
                access_token,
                issuer=self.token_builder_4.issuer,
                audience=self.token_builder_4.audience,
            )

    # def test_max_jwks_age(self):
    #     # Feature not implemented.
    #     assert 0
