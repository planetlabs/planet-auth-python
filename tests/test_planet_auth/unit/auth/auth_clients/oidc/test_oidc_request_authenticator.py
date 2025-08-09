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

from unittest.mock import MagicMock

import freezegun
import pathlib
import tempfile
import unittest

from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.request_authenticator import (
    RefreshingOidcTokenRequestAuthenticator,
    RefreshOrReloginOidcTokenRequestAuthenticator,
)
from tests.test_planet_auth.unit.auth.util import StubOidcClientConfig, StubOidcAuthClient
from tests.test_planet_auth.util import tdata_resource_file_path

TEST_TOKEN_TTL = 8
TEST_TOKEN_AUDENCE = "__RefreshingOidcRequestAuthenticator_utest_audience__"
TEST_SIGNING_KEY_FILE = tdata_resource_file_path("keys/keypair1_priv_nopassword.test_pem")
TEST_SIGNING_PUBKEY_FILE = tdata_resource_file_path("keys/keypair1_pub_jwk.json")
TEST_AUTH_SERVER = "https://blackhole.unittest.planet.com/oauth2"

TEST_STUB_CLIENT_CONFIG = StubOidcClientConfig(
    auth_server=TEST_AUTH_SERVER,
    stub_authority_ttl=TEST_TOKEN_TTL,
    stub_authority_access_token_audience=TEST_TOKEN_AUDENCE,
    stub_authority_signing_key_file=TEST_SIGNING_KEY_FILE,
    stub_authority_pub_key_file=TEST_SIGNING_PUBKEY_FILE,
    scopes=["offline_access", "profile", "openid", "test_scope_1", "test_scope_2"],
)


class ORAUnitTestException(Exception):
    pass


class RefreshFailingStubOidcAuthClient(StubOidcAuthClient):
    def refresh(self, refresh_token, requested_scopes=None, extra=None, **kwargs):
        raise ORAUnitTestException("Forced test exception")


class RefreshingOidcRequestAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        # we use the stub auth client for generating initial state, and the
        # mock auth client for probing authenticator behavior.
        self.stub_auth_client = StubOidcAuthClient(TEST_STUB_CLIENT_CONFIG)
        self.wrapped_stub_auth_client = MagicMock(wraps=self.stub_auth_client)
        self.refresh_failing_auth_client = RefreshFailingStubOidcAuthClient(TEST_STUB_CLIENT_CONFIG)
        self.wrapper_refresh_failing_auth_client = MagicMock(wraps=self.refresh_failing_auth_client)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_dir_path = pathlib.Path(self.tmp_dir.name)

    def under_test_happy_path(self):
        credential_path = self.tmp_dir_path / "refreshing_oidc_authenticator_test_token__with_refresh.json"
        test_credential = self.mock_auth_login_and_command_initialize(
            credential_path=credential_path, auth_client=self.stub_auth_client
        )
        return RefreshingOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.wrapped_stub_auth_client
        )

    def under_test_happy_path_in_memory(self):
        test_credential = self.mock_auth_login_and_command_initialize_in_memory(
            credential_path=None, auth_client=self.stub_auth_client
        )
        return RefreshingOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.wrapped_stub_auth_client
        )

    def under_test_no_refresh_token(self):
        credential_path = self.tmp_dir_path / "refreshing_oidc_authenticator_test_token__without_refresh.json"
        test_credential = self.mock_auth_login_and_command_initialize(
            credential_path=credential_path, auth_client=self.stub_auth_client, get_refresh_token=False
        )
        return RefreshingOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.wrapped_stub_auth_client
        )

    def under_test_no_auth_client(self):
        credential_path = self.tmp_dir_path / "refreshing_oidc_authenticator_test_token__no_client_provided.json"
        test_credential = self.mock_auth_login_and_command_initialize(
            credential_path=credential_path, auth_client=self.stub_auth_client
        )
        return RefreshingOidcTokenRequestAuthenticator(credential=test_credential, auth_client=None)

    def under_test_no_access_token(self):
        credential_path = self.tmp_dir_path / "refreshing_oidc_authenticator_test_token__no_access_token.json"
        test_credential = self.mock_auth_login_and_command_initialize(
            credential_path=credential_path, auth_client=self.stub_auth_client, get_access_token=False
        )
        return RefreshingOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.wrapped_stub_auth_client
        )

    def under_test_refresh_fails(self):
        credential_path = self.tmp_dir_path / "refreshing_oidc_authenticator_test_token__refresh_fails.json"
        test_credential = self.mock_auth_login_and_command_initialize(
            credential_path=credential_path, auth_client=self.refresh_failing_auth_client
        )
        return RefreshingOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.wrapper_refresh_failing_auth_client
        )

    @staticmethod
    def mock_auth_login_and_command_initialize(
        credential_path, auth_client, get_access_token=True, get_id_token=True, get_refresh_token=True
    ):
        # pretend to bootstrap client auth configuration on disk, the way
        # it may be used by a user in an interactive shell:

        # bash$ planet auth login
        initial_credential = auth_client.login(
            get_access_token=get_access_token, get_refresh_token=get_refresh_token, get_id_token=get_id_token
        )
        initial_credential.set_path(credential_path)
        initial_credential.save()
        # <planet auth login process exits>

        # bash$ planet <some API command>
        #       # sets up credential object to be lazy loaded.
        test_credential = FileBackedOidcCredential(credential_file=credential_path)
        #       # The command would then use this credential and an
        #       # authenticator to interact with a planet API. Take it away,
        #       # test case...
        return test_credential

    @staticmethod
    def mock_auth_login_and_command_initialize_in_memory(
        credential_path, auth_client, get_access_token=True, get_id_token=True, get_refresh_token=True
    ):
        # pretend to bootstrap client auth in memory, the way
        # it may be used in a notebook or some other environment
        # where saving to disk is not available.
        # TODO: is this how you would go about this?

        # bash$ planet auth login would do this
        initial_credential = auth_client.login(
            get_access_token=get_access_token, get_refresh_token=get_refresh_token, get_id_token=get_id_token
        )
        initial_credential.set_path(credential_path)
        initial_credential.save()  # Should do nothing.

        # <planet auth login process would exit. We assume an in memory user does not.>
        return initial_credential

    @staticmethod
    def mock_api_call(under_test):
        # We don't need to actually mock making an HTTP API call. That is all
        # unit tested with the base class, and the OIDC authenticators don't
        # actually touch that. They only interact via the base class
        # pre_request_hook()
        under_test.pre_request_hook()

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_happy_path_1(self, frozen_time):
        # The first API call should trigger a token load from disk.
        # If the token is current, the auth client should be untouched.
        under_test = self.under_test_happy_path()

        self.assertIsNone(under_test._credential.data())
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t1 = under_test._credential.access_token()

        # inside the refresh window, more access should not refresh
        self.mock_api_call(under_test)
        self.mock_api_call(under_test)
        self.mock_api_call(under_test)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(access_token_t1, access_token_t2)

        # When the token reaches the 3/4 life, the authenticator should
        # attempt a token refresh
        frozen_time.tick(((3 * TEST_TOKEN_TTL) / 4) + 2)
        self.mock_api_call(under_test)
        self.assertEqual(1, under_test._auth_client.refresh.call_count)
        access_token_t3 = under_test._credential.access_token()
        self.assertNotEqual(access_token_t1, access_token_t3)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_happy_path_1_in_memory(self, frozen_time):
        # The first API call should trigger a token load from disk.
        # If the token is current, the auth client should be untouched.
        under_test = self.under_test_happy_path_in_memory()

        under_test._credential.check()  # Should have a fully valid credential
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t1 = under_test._credential.access_token()

        # inside the refresh window, more access should not refresh
        self.mock_api_call(under_test)
        self.mock_api_call(under_test)
        self.mock_api_call(under_test)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(access_token_t1, access_token_t2)

        # When the token reaches the 3/4 life, the authenticator should
        # attempt a token refresh
        frozen_time.tick(((3 * TEST_TOKEN_TTL) / 4) + 2)
        self.mock_api_call(under_test)
        self.assertEqual(1, under_test._auth_client.refresh.call_count)
        access_token_t3 = under_test._credential.access_token()
        self.assertNotEqual(access_token_t1, access_token_t3)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_happy_path_2(self, frozen_time):
        # The first API call should trigger a token load.
        # If the token is past the refresh time, a token refresh should be
        # attempted before the first use
        under_test = self.under_test_happy_path()

        frozen_time.tick(TEST_TOKEN_TTL + 2)
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(1, under_test._auth_client.refresh.call_count)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_refresh_fails(self, frozen_time):
        # Refresh could fail.  If it does, this should be buried and we
        # should try to carry on with the token we have.
        # (this is why we refresh before expiry, so transient failures
        # do not stop work). Of course, eventually the token will be no good,
        # and this is expected to generate API errors.
        under_test = self.under_test_refresh_fails()

        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        self.mock_api_call(under_test)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t1 = under_test._credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        self.mock_api_call(under_test)
        self.assertEqual(1, under_test._auth_client.refresh.call_count)
        access_token_t2 = under_test._credential.access_token()

        self.assertEqual(access_token_t1, access_token_t2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_no_refresh_token(self, frozen_time):
        # if we have no refresh token, what happens when we expect to
        # refresh? It's not expected that a user use the refreshing
        # authenticator when not using a refresh token (there is another
        # authenticator for this), but you never know what people will do.
        # This should be treated like any other refresh failure (above).
        # We continue with what we have. (and while we would never expect a
        # call to refresh to work without a refresh token, that decision is
        # delegated to the auth server.)
        under_test = self.under_test_no_refresh_token()

        self.mock_api_call(under_test)
        access_token_t1 = under_test._credential.access_token()
        self.assertEqual(0, under_test._auth_client.refresh.call_count)

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        self.mock_api_call(under_test)
        self.assertEqual(1, under_test._auth_client.refresh.call_count)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(access_token_t1, access_token_t2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_no_auth_client(self, frozen_time):
        # when no auth client is provided, just authenticate with what we
        # have.
        under_test = self.under_test_no_auth_client()

        self.mock_api_call(under_test)
        access_token_t1 = under_test._credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        self.mock_api_call(under_test)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(access_token_t1, access_token_t2)

    def test_no_access_token(self):
        # Test credential has no access token, but it does have a refresh
        # token. We would not expect clients that want to use APIs to have
        # such credentials, but you never know what people will try!
        # It's up to the API endpoint to decide if "no auth" is valid.
        # For some endpoints, this may be valid (e.g. public discovery
        # endpoints.)
        #
        # This is not expected to be a normal path, but we should behave.
        # It allows an application to potentially be bootstrap with just
        # a refresh token.
        under_test = self.under_test_no_access_token()
        access_token_t1 = under_test._credential.access_token()
        self.assertIsNone(access_token_t1)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        self.mock_api_call(under_test)
        self.assertEqual(1, under_test._auth_client.refresh.call_count)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_out_of_band_update_1(self, frozen_time):
        # Out of band credential update.  We expect the refresher to reload
        # the credential file without attempting a refresh.
        under_test = self.under_test_happy_path()

        self.assertIsNone(under_test._credential.data())
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t1 = under_test._credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        credential_t1 = under_test._credential
        oob_credential = self.stub_auth_client.refresh(credential_t1.refresh_token())
        oob_credential.set_path(credential_t1.path())
        oob_credential.save()
        access_token_oob = oob_credential.access_token()

        # The new token is within TTL, and a refresh should not occure
        self.mock_api_call(under_test)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        self.assertNotEqual(access_token_t1, access_token_t2)
        self.assertEqual(access_token_oob, access_token_t2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_out_of_band_update_2(self, frozen_time):
        # Out of band credential update.  Something updated the credential
        # on disk underneath us. We expect the refresher to reload
        # the credential file without attempting a refresh.
        under_test = self.under_test_happy_path()

        self.assertIsNone(under_test._credential.data())
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        access_token_t1 = under_test._credential.access_token()

        credential_t1 = under_test._credential
        oob_credential = self.stub_auth_client.refresh(credential_t1.refresh_token())
        oob_credential.set_path(credential_t1.path())
        oob_credential.save()
        access_token_oob = oob_credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        # The new token is outside TTL, even after the token is reloaded, this
        # should be detected and a refresh should still occur.
        self.mock_api_call(under_test)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(1, under_test._auth_client.refresh.call_count)
        self.assertNotEqual(access_token_t1, access_token_t2)
        self.assertNotEqual(access_token_oob, access_token_t2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_side_band_update_credential(self, frozen_time):
        # a side-band update of the credential should reset our "refresh at" time,
        # cascading behavior from there.  Where the above happens when someone
        # modifies a credential on disk, this happens when something in memory
        # provides us with a new credential, but it not the Authenticator's internal
        # self refreshing capabilities.
        under_test = self.under_test_happy_path()

        # The happy path under test primes brand new but *unloaded* credential that has been saved to disk.
        self.assertIsNone(under_test._credential.data())
        self.assertEqual(0, under_test._refresh_at)

        self.mock_api_call(under_test)  # Loads a valid token JIT.

        self.assertNotEqual(0, under_test._refresh_at)
        initial_access_token = under_test._credential.access_token()
        self.assertIsNotNone(initial_access_token)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)

        # Get the sideband credential when we would have expected a refresh to probe behavior.
        frozen_time.tick(TEST_TOKEN_TTL + 2)
        sideband_credential_path = self.tmp_dir_path / "test_sideband.json"
        sideband_credential = self.mock_auth_login_and_command_initialize(
            credential_path=sideband_credential_path, auth_client=self.stub_auth_client
        )

        under_test.update_credential(sideband_credential)

        self.assertEqual(0, under_test._refresh_at)

        self.mock_api_call(under_test)  # Loads a valid token JIT.

        self.assertNotEqual(0, under_test._refresh_at)
        current_access_token = under_test._credential.access_token()
        self.assertEqual(sideband_credential.access_token(), current_access_token)
        self.assertNotEqual(initial_access_token, current_access_token)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)

    # def test_side_band_update_credential_in_memory(self):
    #     under_test = self.under_test_happy_path_in_memory()

    def test_side_band_update_credential_data(self):
        # Similar to above, the credential is updated by a
        # side-band call to update the data.
        under_test = self.under_test_happy_path()
        self.mock_api_call(under_test)  # Should ensure that our old data is all primed and used
        initial_credential_data = under_test.credential().data()

        # abuse login to dummy up some other valid credential structure.
        sideband_credential = self.stub_auth_client.login(
            get_access_token=True, get_refresh_token=True, get_id_token=False
        )
        under_test.update_credential_data(sideband_credential.data())

        # update_credential_data() should leave is us in a freshly _load()'ed state.
        # It should not be necessary to simulate an API call for everything to be set
        current_credential_data = under_test._credential.data()
        self.assertNotEqual(current_credential_data, initial_credential_data)
        self.assertEqual(current_credential_data, sideband_credential.data())
        self.assertEqual(under_test._token_body, sideband_credential.access_token())
        self.assertNotEqual(0, under_test._refresh_at)
        self.assertNotEqual(0, under_test._credential._load_time)


class RefreshOrReloginOidcRequestAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        # we use the stub auth client for generating initial state, and the
        # mock auth client for probing authenticator behavior.
        self.stub_auth_client = StubOidcAuthClient(TEST_STUB_CLIENT_CONFIG)
        self.mock_auth_client = MagicMock(wraps=self.stub_auth_client)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_dir_path = pathlib.Path(self.tmp_dir.name)

    def under_test_with_refresh_token(self):
        credential_path = self.tmp_dir_path / "refreshing_or_relogin_oidc_authenticator_test_token__with_refresh.json"
        test_credential = self.mock_auth_login_and_command_initialize(credential_path)
        return RefreshOrReloginOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.mock_auth_client
        )

    def under_test_without_refresh_token(self):
        credential_path = (
            self.tmp_dir_path / "refreshing_or_relogin_oidc_authenticator_test_token__without_refresh.json"
        )
        test_credential = self.mock_auth_login_and_command_initialize(credential_path, get_refresh_token=False)
        return RefreshOrReloginOidcTokenRequestAuthenticator(
            credential=test_credential, auth_client=self.mock_auth_client
        )

    def under_test_no_auth_client(self):
        credential_path = (
            self.tmp_dir_path / "refreshing_or_relogin_oidc_authenticator_test_token__no_client_provided.json"
        )
        test_credential = self.mock_auth_login_and_command_initialize(credential_path)
        return RefreshOrReloginOidcTokenRequestAuthenticator(credential=test_credential, auth_client=None)

    def mock_auth_login_and_command_initialize(
        self, credential_path, get_access_token=True, get_id_token=True, get_refresh_token=True
    ):
        # pretend to bootstrap client auth configuration on disk, the way
        # it may be used by a user in an interactive shell:

        # bash$ planet auth login
        test_credential = self.stub_auth_client.login(
            get_access_token=get_access_token, get_refresh_token=get_refresh_token, get_id_token=get_id_token
        )
        test_credential.set_path(credential_path)
        test_credential.save()
        # <planet auth login process exits>

        # bash$ planet <some API command>
        #       # sets up credential object to be lazy loaded.
        test_credential = FileBackedOidcCredential(credential_file=credential_path)
        #       # The command would then use this credential and an
        #       # authenticator to interact with a planet API. Take it away,
        #       # test case...
        return test_credential

    def mock_api_call(self, under_test):
        # We don't need to actually mock making an HTTP API call. That is all
        # unit tested with the base class, and the OIDC authenticators don't
        # actually touch that. They only interact via the base class
        # pre_request_hook()
        under_test.pre_request_hook()

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_refresh_token_calls_refresh(self, frozen_time):
        under_test = self.under_test_with_refresh_token()

        self.assertIsNone(under_test._credential.data())
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        self.assertEqual(0, under_test._auth_client.login.call_count)
        access_token_t1 = under_test._credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        self.mock_api_call(under_test)
        self.assertEqual(1, under_test._auth_client.refresh.call_count)
        self.assertEqual(0, under_test._auth_client.login.call_count)
        access_token_t2 = under_test._credential.access_token()
        self.assertNotEqual(access_token_t1, access_token_t2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_no_refresh_token_calls_login(self, frozen_time):
        under_test = self.under_test_without_refresh_token()

        self.assertIsNone(under_test._credential.data())
        self.mock_api_call(under_test)
        self.assertIsNotNone(under_test._credential.data())
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        self.assertEqual(0, under_test._auth_client.login.call_count)
        access_token_t1 = under_test._credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        self.mock_api_call(under_test)
        self.assertEqual(0, under_test._auth_client.refresh.call_count)
        self.assertEqual(1, under_test._auth_client.login.call_count)
        access_token_t2 = under_test._credential.access_token()
        self.assertNotEqual(access_token_t1, access_token_t2)

    @freezegun.freeze_time(as_kwarg="frozen_time")
    def test_no_auth_client(self, frozen_time):
        # when no auth client is provided, just authenticate with what we
        # have.
        under_test = self.under_test_no_auth_client()

        self.mock_api_call(under_test)
        access_token_t1 = under_test._credential.access_token()

        frozen_time.tick(TEST_TOKEN_TTL + 2)

        self.mock_api_call(under_test)
        access_token_t2 = under_test._credential.access_token()
        self.assertEqual(access_token_t1, access_token_t2)
