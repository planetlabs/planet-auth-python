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

import inspect
import jwt.utils
import secrets
import time
import uuid
import re
from unittest import mock

import pytest

from planet_auth import ScopeNotGrantedTokenException, InvalidArgumentException
from planet_auth.auth import Auth
from planet_auth.auth_client import AuthClient, AuthClientConfig
from planet_auth.oidc.auth_clients.client_validator import OidcClientValidatorAuthClient
from planet_auth.oidc.auth_clients.client_credentials_flow import ClientCredentialsClientSecretAuthClient
from planet_auth.auth_exception import AuthException, InvalidTokenException
from planet_auth.oidc.multi_validator import OidcMultiIssuerValidator
from tests.test_planet_auth.unit.auth.util import StubOidcAuthClient, StubOidcClientConfig, FakeTokenBuilder
from tests.test_planet_auth.util import tdata_resource_file_path

# TEST_AUTH_SERVER = "https://blackhole.unittest.planet.com/oauth2"
TEST_PRIMARY_ISSUER = "test_primary_issuer"
TEST_PRIMARY_SIGNING_KEY = tdata_resource_file_path("keys/keypair1_priv_nopassword.test_pem")
TEST_PRIMARY_PUB_KEY = tdata_resource_file_path("keys/keypair1_pub_jwk.json")

TEST_SECONDARY_ISSUER = "test_secondary_issuer"
TEST_SECONDARY_SIGNING_KEY = tdata_resource_file_path("keys/keypair2_priv_nopassword.test_pem")
TEST_SECONDARY_PUB_KEY = tdata_resource_file_path("keys/keypair2_pub_jwk.json")

TEST_UNTRUSTED_ISSUER = "test_untrusted_issuer"
TEST_UNTRUSTED_SIGNING_KEY = tdata_resource_file_path("keys/keypair3_priv_nopassword.test_pem")
TEST_UNTRUSTED_PUB_KEY = tdata_resource_file_path("keys/keypair3_pub_jwk.json")

TEST_AUDIENCE = "test_audience"

TEST_TOKEN_TTL = 60


#
# Since the return values are governed by different standards,
# there is a lot more ways for remote validation to be considered
# invalid.  This may be redundant with testing of the lower level
# classes, but auth is so important to get right, this is OK by me.
#
class StubOidcAuthClient_ForceFailRemoteValidation(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        raise AuthException("Forced test failure")


class StubOidcAuthClient_InvalidRemoteValidation1(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        # Not a legal response. Errors are supposed to throw
        return None


class StubOidcAuthClient_InvalidRemoteValidation2(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        # Not a legal response. Errors are supposed to throw
        return {}


class StubOidcAuthClient_InvalidRemoteValidation3(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        # Not a legal response. Missing "active" key.  (Is this our job, or the job of the IntrospectionApiClient to enforce?)
        return {"some_key": "some_value"}


class StubOidcAuthClient_InvalidRemoteValidation4(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        # Not a legal response. value is not a bool.
        return {"active": "true"}


class StubOidcAuthClient_InvalidRemoteValidation5(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        # Not a legal response. value is not a bool.
        return {"active": False}


class MVUnitTestException(Exception):
    pass


class StubOidcAuthClient_InvalidRemoteValidation6(StubOidcAuthClient):
    def validate_access_token_remote(self, access_token: str) -> dict:
        raise MVUnitTestException("Unexpected exception class")


class StubOidcAuthClient_InvalidLocalValidation1(StubOidcAuthClient):
    def validate_access_token_local(
        self, access_token: str, required_audience: str = None, scopes_anyof: list = None
    ) -> dict:
        # Not a legal response. Errors are supposed to throw
        return None


class StubOidcAuthClient_InvalidLocalValidation2(StubOidcAuthClient):
    def validate_access_token_local(
        self, access_token: str, required_audience: str = None, scopes_anyof: list = None
    ) -> dict:
        return {}


primary_issuer_config_dict = {
    "auth_server": TEST_PRIMARY_ISSUER,
    "scopes": ["test_scp0", "test_scp1"],
    "audiences": [TEST_AUDIENCE],
    "stub_authority_ttl": TEST_TOKEN_TTL,
    "stub_authority_access_token_audience": TEST_AUDIENCE,
    "stub_authority_signing_key_file": TEST_PRIMARY_SIGNING_KEY,
    "stub_authority_pub_key_file": TEST_PRIMARY_PUB_KEY,
}
primary_issuer_config = StubOidcClientConfig(**primary_issuer_config_dict)

secondary_issuer_config_dict = {
    "auth_server": TEST_SECONDARY_ISSUER,
    "scopes": ["test_scp0", "test_scp2"],
    "audiences": [TEST_AUDIENCE],
    "stub_authority_ttl": TEST_TOKEN_TTL,
    "stub_authority_access_token_audience": TEST_AUDIENCE,
    "stub_authority_signing_key_file": TEST_SECONDARY_SIGNING_KEY,
    "stub_authority_pub_key_file": TEST_SECONDARY_PUB_KEY,
}
secondary_issuer_config = StubOidcClientConfig(**secondary_issuer_config_dict)

untrusted_issuer_config_dict = {
    "auth_server": TEST_UNTRUSTED_ISSUER,
    "scopes": ["test_scp0", "test_scp2"],
    "audiences": [TEST_AUDIENCE],
    "stub_authority_ttl": TEST_TOKEN_TTL,
    "stub_authority_access_token_audience": TEST_AUDIENCE,
    "stub_authority_signing_key_file": TEST_UNTRUSTED_SIGNING_KEY,
    "stub_authority_pub_key_file": TEST_UNTRUSTED_PUB_KEY,
}
untrusted_issuer_config = StubOidcClientConfig(**untrusted_issuer_config_dict)

bad_config_1_dict = {
    "auth_server": TEST_PRIMARY_ISSUER,
    "scopes": ["test_scp0", "test_scp1"],
    "audiences": None,  # Missing
    "stub_authority_ttl": TEST_TOKEN_TTL,
    "stub_authority_access_token_audience": TEST_AUDIENCE,
    "stub_authority_signing_key_file": TEST_PRIMARY_SIGNING_KEY,
    "stub_authority_pub_key_file": TEST_PRIMARY_PUB_KEY,
}
bad_config_1 = StubOidcClientConfig(**bad_config_1_dict)

primary_issuer = StubOidcAuthClient(primary_issuer_config)
secondary_issuer = StubOidcAuthClient(secondary_issuer_config)
untrusted_issuer = StubOidcAuthClient(untrusted_issuer_config)
bad_validator_1 = StubOidcAuthClient(bad_config_1)

primary_failRemote = StubOidcAuthClient_ForceFailRemoteValidation(primary_issuer_config)
primary_invalidRemote1 = StubOidcAuthClient_InvalidRemoteValidation1(primary_issuer_config)
primary_invalidRemote2 = StubOidcAuthClient_InvalidRemoteValidation2(primary_issuer_config)
primary_invalidRemote3 = StubOidcAuthClient_InvalidRemoteValidation3(primary_issuer_config)
primary_invalidRemote4 = StubOidcAuthClient_InvalidRemoteValidation4(primary_issuer_config)
primary_invalidRemote5 = StubOidcAuthClient_InvalidRemoteValidation5(primary_issuer_config)
# primary_invalidRemote6 = StubOidcAuthClient_InvalidRemoteValidation6(primary_issuer_config)
primary_invalidLocal1 = StubOidcAuthClient_InvalidLocalValidation1(primary_issuer_config)
primary_invalidLocal2 = StubOidcAuthClient_InvalidLocalValidation2(primary_issuer_config)

secondary_failRemote = StubOidcAuthClient_ForceFailRemoteValidation(secondary_issuer_config)
secondary_invalidRemote1 = StubOidcAuthClient_InvalidRemoteValidation1(secondary_issuer_config)
secondary_invalidRemote2 = StubOidcAuthClient_InvalidRemoteValidation2(secondary_issuer_config)
secondary_invalidRemote3 = StubOidcAuthClient_InvalidRemoteValidation3(secondary_issuer_config)
secondary_invalidRemote4 = StubOidcAuthClient_InvalidRemoteValidation4(secondary_issuer_config)
secondary_invalidRemote5 = StubOidcAuthClient_InvalidRemoteValidation5(secondary_issuer_config)
# secondary_invalidRemote6 = StubOidcAuthClient_InvalidRemoteValidation6(secondary_issuer_config)
secondary_invalidLocal1 = StubOidcAuthClient_InvalidLocalValidation1(secondary_issuer_config)
secondary_invalidLocal2 = StubOidcAuthClient_InvalidLocalValidation2(secondary_issuer_config)


class TestMultiValidator:
    # TODO: rather than monkey patch, let the validator take auth clients as arguments?
    #       This would also let us maybe handle other auth mechanisms beyond oauth?
    @staticmethod
    def _patch_primary(under_test: OidcMultiIssuerValidator, patched_auth_client: AuthClient):
        under_test._trusted[TEST_PRIMARY_ISSUER]._auth_client = patched_auth_client

    @staticmethod
    def _patch_secondary(under_test: OidcMultiIssuerValidator, patched_auth_client: AuthClient):
        under_test._trusted[TEST_SECONDARY_ISSUER]._auth_client = patched_auth_client

    def under_test__only_primary_validator(self, log_primary=True):
        under_test = OidcMultiIssuerValidator(
            trusted=[Auth.initialize_from_client(auth_client=primary_issuer)], log_result=log_primary
        )
        self._patch_primary(under_test, primary_issuer)
        return under_test

    def under_test__primary_and_secondary_validator(self, log_primary=True, log_secondary=True):
        under_test = OidcMultiIssuerValidator(
            trusted=[Auth.initialize_from_client(primary_issuer), Auth.initialize_from_client(secondary_issuer)],
            log_result=log_primary,
        )
        return under_test

    def under_test__bad_client_1(self):
        under_test = OidcMultiIssuerValidator(trusted=[Auth.initialize_from_client(bad_validator_1)])
        return under_test

    def username(self, test_case_name):
        return test_case_name + "_username"

    def assert_successful_validation_local(self, test_case_name, local_validation, required_issuer):
        # validation failure should throw. spot check some claims for good
        # measure when we need to assert validation success.
        assert TEST_AUDIENCE == local_validation.get("aud")
        assert test_case_name == local_validation.get("test_case")
        assert required_issuer == local_validation.get("iss")

    def assert_successful_validation_remote(self, test_case_name, remote_validation, required_issuer):
        # validation failure should throw. spot check some claims for good
        # measure when we need to assert validation success.
        test_username = self.username(test_case_name)
        assert remote_validation.get("active")
        assert TEST_AUDIENCE == remote_validation.get("aud")
        assert required_issuer == remote_validation.get("iss")
        assert test_username == remote_validation.get("sub")

    def test__primary_only__local_validation_only__success(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__only_primary_validator()
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )

        self.assert_successful_validation_local(test_case_name, local_validation, TEST_PRIMARY_ISSUER)
        assert remote_validation is None

    def test_empty_access_token(self):
        # QE TC3, TC5
        under_test = self.under_test__only_primary_validator()
        with pytest.raises(InvalidArgumentException):
            local_validation, remote_validation = under_test.validate_access_token(token=None)
        with pytest.raises(InvalidArgumentException):
            local_validation, remote_validation = under_test.validate_access_token(token="")

    def test_malformed_token_1(self):
        # QE TC6 - just some random garbage.
        under_test = self.under_test__only_primary_validator()
        with pytest.raises(InvalidTokenException):
            under_test.validate_access_token(token=secrets.token_bytes(2048))

    def test_malformed_token_2(self):
        # QE TC6 - just some random garbage, but URL safe.
        under_test = self.under_test__only_primary_validator()
        with pytest.raises(InvalidTokenException):
            under_test.validate_access_token(token=secrets.token_urlsafe(2048))

    def test_malformed_token_3(self):
        # QE TC6 - random garbage, but has JWT three dot structure.
        under_test = self.under_test__only_primary_validator()
        fake_jwt = "{}.{}.{}".format(
            str(jwt.utils.base64url_encode(secrets.token_bytes(256)), encoding="utf-8"),
            str(jwt.utils.base64url_encode(secrets.token_bytes(2048)), encoding="utf-8"),
            str(jwt.utils.base64url_encode(secrets.token_bytes(256)), encoding="utf-8"),
        )

        with pytest.raises(InvalidTokenException):
            under_test.validate_access_token(token=fake_jwt)

    def test_malformed_token_4(self):
        # QE TC6 - random garbage, but looks more JWT like with encoded json.  Signature is garbage.
        under_test = self.under_test__only_primary_validator()

        fake_jwt = FakeTokenBuilder.fake_token(
            body={
                "fake_claim_1": "test claim value",
                "fake_claim_2": "test claim value",
                "iss": primary_issuer.token_builder.issuer,
            },
            header={
                "alg": primary_issuer.token_builder.signing_key_algorithm,
                "kid": primary_issuer.token_builder.signing_key_id,
            },
        )

        with pytest.raises(InvalidTokenException):
            under_test.validate_access_token(token=fake_jwt)

    def test_malformed_token_5_iss_liars(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)
        under_test = self.under_test__only_primary_validator()

        now = int(time.time())
        token_body = {
            "iss": primary_issuer.token_builder.issuer,
            "sub": test_username,
            "aud": primary_issuer.token_builder.audience,
            "iat": now,
            "exp": now + 100,
            "jti": str(uuid.uuid4()),
        }
        token_header = {
            "alg": primary_issuer.token_builder.signing_key_algorithm,
            "kid": primary_issuer.token_builder.signing_key_id,
        }

        # TC 0
        # Build a valid token first, just to make sure our test method is valid
        test_jwt = primary_issuer.token_builder.encode(body=token_body, extra_headers=token_header)
        under_test.validate_access_token(token=test_jwt)  # No throw

        # TC 1
        # Use the real signing key, but make the iss an invalid type.
        # You can make the argument this is still valid, because the signature is still
        # from a trusted issuer. But, we reject it based on bad structure.
        token_body["iss"] = [primary_issuer.token_builder.issuer, untrusted_issuer.token_builder.issuer]
        test_jwt = primary_issuer.token_builder.encode(body=token_body, extra_headers=token_header)
        with pytest.raises(
            InvalidTokenException,
            match=re.escape("Issuer claim ('iss') must be a of string type. 'list' type was detected."),
        ):
            under_test.validate_access_token(token=test_jwt)

        # TC 2
        # Liar token.  Untrusted issuer signing key claiming to be valid issuer
        token_body["iss"] = primary_issuer.token_builder.issuer
        test_jwt = untrusted_issuer.token_builder.encode(body=token_body, extra_headers=token_header)
        with pytest.raises(
            InvalidTokenException, match=re.escape("Signature verification failed (InvalidSignatureError)")
        ):
            under_test.validate_access_token(token=test_jwt)

        # TC 3
        # Double-talk liar.  Using the untrusted signing key, claiming to be ourselves and the trusted issuer.
        token_body["iss"] = [primary_issuer.token_builder.issuer, untrusted_issuer.token_builder.issuer]
        test_jwt = untrusted_issuer.token_builder.encode(body=token_body, extra_headers=token_header)
        with pytest.raises(
            InvalidTokenException,
            match=re.escape("Issuer claim ('iss') must be a of string type. 'list' type was detected."),
        ):
            under_test.validate_access_token(token=test_jwt)

    def test_missing_signature(self):
        # QE TC11 - JWT without a signature
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)
        under_test = self.under_test__only_primary_validator()

        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        token_parts = access_token.access_token().split(".")

        # test the test, make sure our mangling technique doesn't cause unexpected problems.
        # This should pass validation without any exceptions.
        mangled_token = "{}.{}.{}".format(token_parts[0], token_parts[1], token_parts[2])
        local_validation, remote_validation = under_test.validate_access_token(token=mangled_token)

        # real test 1 - with the last "."
        mangled_token = "{}.{}.".format(token_parts[0], token_parts[1])
        with pytest.raises(InvalidTokenException):
            local_validation, remote_validation = under_test.validate_access_token(token=mangled_token)

        # real test 2 - without the last "."
        mangled_token = "{}.{}".format(token_parts[0], token_parts[1])
        with pytest.raises(InvalidTokenException):
            local_validation, remote_validation = under_test.validate_access_token(token=mangled_token)

    def test_malformed_token_missing_issuer(self):
        # QE TC14
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)
        access_token = primary_issuer.login(
            username=test_username, extra_claims={"test_case": test_case_name}, remove_claims=["iss"]
        )

        under_test = self.under_test__only_primary_validator()
        with pytest.raises(InvalidTokenException):
            under_test.validate_access_token(token=access_token.access_token())

    def test__primary_only__local_validation_only__test_scope_validation(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__only_primary_validator()

        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False, scopes_anyof=None
        )
        self.assert_successful_validation_local(test_case_name, local_validation, TEST_PRIMARY_ISSUER)

        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False, scopes_anyof=[]
        )
        self.assert_successful_validation_local(test_case_name, local_validation, TEST_PRIMARY_ISSUER)

        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(),
            do_remote_revocation_check=False,
            scopes_anyof=["test_scp1", "some_scome_not_in_the_token"],
        )
        self.assert_successful_validation_local(test_case_name, local_validation, TEST_PRIMARY_ISSUER)

        with pytest.raises(ScopeNotGrantedTokenException):
            under_test.validate_access_token(
                access_token.access_token(), do_remote_revocation_check=False, scopes_anyof=["test_missing_scope"]
            )

    def test__primary_only__local_and_remote_validation__success(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__only_primary_validator()
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=True
        )

        self.assert_successful_validation_local(test_case_name, local_validation, TEST_PRIMARY_ISSUER)
        self.assert_successful_validation_remote(test_case_name, remote_validation, TEST_PRIMARY_ISSUER)

    @pytest.mark.parametrize("failing_locally_primary_issuer", [(primary_invalidLocal1), (primary_invalidLocal2)])
    def test__primary_only__fail_local_validation(self, failing_locally_primary_issuer):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__only_primary_validator()
        self._patch_primary(under_test, failing_locally_primary_issuer)

        with pytest.raises(AuthException):
            local_validation, remote_validation = under_test.validate_access_token(
                access_token.access_token(), do_remote_revocation_check=False
            )

    @pytest.mark.parametrize(
        "failing_remote_primary_issuer",
        [
            (primary_failRemote),
            (primary_invalidRemote1),
            (primary_invalidRemote2),
            (primary_invalidRemote3),
            (primary_invalidRemote4),
            (primary_invalidRemote5),
            # (primary_invalidRemote6),
        ],
    )
    def test__primary_only__fail_remote_validation(self, failing_remote_primary_issuer):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__only_primary_validator()
        self._patch_primary(under_test, failing_remote_primary_issuer)

        # Local check passes
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )
        self.assert_successful_validation_local(test_case_name, local_validation, TEST_PRIMARY_ISSUER)
        assert remote_validation is None

        # Remote check fails
        with pytest.raises(AuthException):
            local_validation, remote_validation = under_test.validate_access_token(
                access_token.access_token(), do_remote_revocation_check=True
            )

    def test__secondary__local_auth_only_success(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = test_case_name + "_username"

        access_token = secondary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator()
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )

        self.assert_successful_validation_local(test_case_name, local_validation, TEST_SECONDARY_ISSUER)
        assert remote_validation is None

    def test__secondary__local_and_remote_auth_success(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = test_case_name + "_username"

        access_token = secondary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator()
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=True
        )

        self.assert_successful_validation_local(test_case_name, local_validation, TEST_SECONDARY_ISSUER)
        self.assert_successful_validation_remote(test_case_name, remote_validation, TEST_SECONDARY_ISSUER)

    @pytest.mark.parametrize(
        "failing_remote_secondary_issuer",
        [
            (secondary_failRemote),
            (secondary_invalidRemote1),
            (secondary_invalidRemote2),
            (secondary_invalidRemote3),
            (secondary_invalidRemote4),
            (secondary_invalidRemote5),
            # (secondary_invalidRemote6),
        ],
    )
    def test__secondary__fail_remote_validation(self, failing_remote_secondary_issuer):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = secondary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator()
        self._patch_secondary(under_test, failing_remote_secondary_issuer)

        # Local check passes
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )
        self.assert_successful_validation_local(test_case_name, local_validation, TEST_SECONDARY_ISSUER)
        assert remote_validation is None

        # Remote check fails
        with pytest.raises(AuthException):
            local_validation, remote_validation = under_test.validate_access_token(
                access_token.access_token(), do_remote_revocation_check=True
            )

    def test_check_auth_client_types(self):
        #  test that we check the types of passed auth clients to the ctor
        with pytest.raises(AuthException):
            OidcMultiIssuerValidator(
                trusted=[
                    Auth.initialize_from_config(
                        client_config=AuthClientConfig.from_file(
                            tdata_resource_file_path("auth_client_configs/utest/planet_legacy.json")
                        )
                    )
                ]
            )
        with pytest.raises(AuthException):
            OidcMultiIssuerValidator(
                trusted=[
                    Auth.initialize_from_client(auth_client=primary_issuer),
                    Auth.initialize_from_config(
                        client_config=AuthClientConfig.from_file(
                            tdata_resource_file_path("auth_client_configs/utest/static_api_key.json")
                        )
                    ),
                ],
            )

    def test_no_repeat_issuers(self):
        with pytest.raises(AuthException):
            OidcMultiIssuerValidator(
                trusted=[Auth.initialize_from_client(primary_issuer), Auth.initialize_from_client(primary_issuer)],
            )
        with pytest.raises(AuthException):
            OidcMultiIssuerValidator(
                trusted=[
                    Auth.initialize_from_client(primary_issuer),
                    Auth.initialize_from_client(secondary_issuer),
                    Auth.initialize_from_client(primary_issuer),
                ],
            )

    def test_ignore_falsy_issuers_in_direct_construction(self):
        under_test = OidcMultiIssuerValidator(
            trusted=["", Auth.initialize_from_client(primary_issuer), None],
        )
        assert len(under_test._trusted) == 1

        under_test = OidcMultiIssuerValidator(
            trusted=[
                "",
                Auth.initialize_from_client(primary_issuer),
                Auth.initialize_from_client(secondary_issuer),
                None,
            ],
        )
        assert len(under_test._trusted) == 2

    def test_ignore_falsy_issuers_in_url_construction(self):
        under_test = OidcMultiIssuerValidator.from_auth_server_urls(
            audience=TEST_AUDIENCE,
            trusted_auth_server_urls=[TEST_PRIMARY_ISSUER, "", None],
        )
        assert len(under_test._trusted) == 1

        under_test = OidcMultiIssuerValidator.from_auth_server_urls(
            audience=TEST_AUDIENCE,
            trusted_auth_server_urls=[TEST_PRIMARY_ISSUER, TEST_SECONDARY_ISSUER, "", None],
        )
        assert len(under_test._trusted) == 2

    def test_ignore_falsy_issuers_in_configdict_construction(self):
        under_test = OidcMultiIssuerValidator.from_auth_server_configs(
            trusted_auth_server_configs=["", primary_issuer_config_dict, None],
        )
        assert len(under_test._trusted) == 1

        under_test = OidcMultiIssuerValidator.from_auth_server_configs(
            trusted_auth_server_configs=[
                "",
                primary_issuer_config_dict,
                secondary_issuer_config_dict,
                None,
            ],
        )
        assert len(under_test._trusted) == 2

    def test_reject_unknown_issuer(self):
        # QE TC15
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        access_token = untrusted_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator()
        with pytest.raises(AuthException):
            local_validation, remote_validation = under_test.validate_access_token(
                access_token.access_token(), do_remote_revocation_check=False
            )

    def test_fail_bad_config_1(self):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = self.username(test_case_name)

        primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        with pytest.raises(AuthException):
            self.under_test__bad_client_1()

    def test_config_dict_construction_happy(self):
        test_conf_dict_1 = {
            "auth_server": TEST_PRIMARY_ISSUER,
            "scopes": ["test_scp0", "test_scp1"],
            "audiences": [TEST_AUDIENCE],
        }
        test_conf_dict_2 = {
            "auth_server": TEST_SECONDARY_ISSUER,
            "scopes": ["test_scp0", "test_scp1"],
            "audiences": [TEST_AUDIENCE],
        }
        under_test = OidcMultiIssuerValidator.from_auth_server_configs(
            trusted_auth_server_configs=[test_conf_dict_1, test_conf_dict_2]
        )
        assert len(under_test._trusted) == 2

    def test_config_dict_construction_sets_client_type(self):
        test_conf_dict = {
            "auth_server": TEST_PRIMARY_ISSUER,
            "scopes": ["test_scp0", "test_scp1"],
            "audiences": [TEST_AUDIENCE],
        }
        under_test = OidcMultiIssuerValidator.from_auth_server_configs(trusted_auth_server_configs=[test_conf_dict])
        assert len(under_test._trusted) == 1
        assert isinstance(under_test._trusted[TEST_PRIMARY_ISSUER].auth_client(), OidcClientValidatorAuthClient)
        assert (
            under_test._trusted[TEST_PRIMARY_ISSUER].auth_client()._oidc_client_config.issuer() == TEST_PRIMARY_ISSUER
        )

        test_conf_dict["client_type"] = "oidc_client_credentials_secret"
        test_conf_dict["client_id"] = "__test_dummy__"
        test_conf_dict["client_secret"] = "__test_dummy__"
        test_conf_dict["issuer"] = "__test_dummy__"
        under_test = OidcMultiIssuerValidator.from_auth_server_configs(trusted_auth_server_configs=[test_conf_dict])
        assert len(under_test._trusted) == 1
        assert isinstance(under_test._trusted["__test_dummy__"].auth_client(), ClientCredentialsClientSecretAuthClient)
        assert under_test._trusted["__test_dummy__"].auth_client()._oidc_client_config.issuer() == "__test_dummy__"

    @mock.patch("planet_auth.logging.auth_logger.AuthLogger.warning")
    @mock.patch("planet_auth.logging.auth_logger.AuthLogger.info")
    def test_primary_logs_as_info(self, mock_auth_logger_info, mock_auth_logger_warning):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = test_case_name + "_username"
        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator(log_primary=True)
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )

        assert mock_auth_logger_info.call_count == 1
        assert mock_auth_logger_warning.call_count == 0

    @mock.patch("planet_auth.logging.auth_logger.AuthLogger.warning")
    @mock.patch("planet_auth.logging.auth_logger.AuthLogger.info")
    def test_primary_logs_disabled(self, mock_auth_logger_info, mock_auth_logger_warning):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = test_case_name + "_username"
        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator(log_primary=False)
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )

        assert mock_auth_logger_info.call_count == 0
        assert mock_auth_logger_warning.call_count == 0

    @mock.patch("planet_auth.logging.auth_logger.AuthLogger.warning")
    @mock.patch("planet_auth.logging.auth_logger.AuthLogger.info")
    def test_primary_logs_by_default(self, mock_auth_logger_info, mock_auth_logger_warning):
        test_case_name = inspect.currentframe().f_code.co_name
        test_username = test_case_name + "_username"
        access_token = primary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        # access_token = secondary_issuer.login(username=test_username, extra_claims={"test_case": test_case_name})
        under_test = self.under_test__primary_and_secondary_validator()
        local_validation, remote_validation = under_test.validate_access_token(
            access_token.access_token(), do_remote_revocation_check=False
        )

        assert mock_auth_logger_info.call_count == 1
        assert mock_auth_logger_warning.call_count == 0
