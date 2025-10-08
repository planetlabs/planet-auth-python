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

import pathlib
import time
import unittest
from typing import List, Optional
from unittest.mock import MagicMock

from planet_auth.auth import Auth, Credential, CredentialRequestAuthenticator, AuthClientContextException
from planet_auth.auth_client import AuthClient, AuthClientConfig, AuthClientException
from planet_auth.auth_exception import AuthException
from planet_auth.static_api_key.auth_client import StaticApiKeyAuthClient
from planet_auth.static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator
from planet_auth.none.noop_auth import NoOpAuthClient

from tests.test_planet_auth.util import tdata_resource_file_path


class AuthTest(unittest.TestCase):
    def test_initialize_from_conffile_with_no_token_file(self):
        under_test = Auth.initialize_from_config(
            client_config=AuthClientConfig.from_file(
                tdata_resource_file_path("auth_client_configs/utest/static_api_key.json")
            ),
        )
        self.assertIsInstance(under_test.auth_client(), StaticApiKeyAuthClient)
        self.assertIsInstance(under_test.request_authenticator(), FileBackedApiKeyRequestAuthenticator)
        self.assertIsNone(under_test.token_file_path())
        self.assertIsNone(under_test.profile_name())

    def test_initialize_from_conffile_with_token_file(self):
        under_test = Auth.initialize_from_config(
            client_config=AuthClientConfig.from_file(
                tdata_resource_file_path("auth_client_configs/utest/static_api_key.json")
            ),
            token_file="/dev/null/test_token.json",
        )
        self.assertIsInstance(under_test.auth_client(), StaticApiKeyAuthClient)
        self.assertIsInstance(under_test.request_authenticator(), FileBackedApiKeyRequestAuthenticator)
        self.assertIsInstance(under_test.token_file_path(), pathlib.Path)
        self.assertEqual(pathlib.Path("/dev/null/test_token.json"), under_test.token_file_path())
        self.assertIsNone(under_test.profile_name())

    def test_initialize_from_config(self):
        under_test = Auth.initialize_from_config_dict(
            client_config={"client_type": "none"}, token_file="/dev/null/token.json"
        )
        self.assertIsInstance(under_test.auth_client(), NoOpAuthClient)
        self.assertEqual(under_test.token_file_path(), pathlib.Path("/dev/null/token.json"))
        self.assertIsNone(under_test.profile_name())

    def test_initialize_from_config_invalid_client(self):
        with self.assertRaises(AuthClientException):
            Auth.initialize_from_config_dict(
                client_config={"client_type": "invalid"}, token_file="/dev/null/token.json"
            )

    def test_initialize_from_config_none_client(self):
        with self.assertRaises(AuthClientException):
            Auth.initialize_from_config_dict(client_config=None, token_file="/dev/null/token.json")


class FakeCredential(Credential):
    """Fake credential with controllable expiration state"""

    def __init__(self, token_ttl=None, is_expired=False, credential_file=None):
        super().__init__(
            data={
                "test_token_ttl": token_ttl,
                "test_token_is_expired": is_expired,
            },
            file_path=credential_file,
        )
        self._augment_data()

    def _augment_data(self):
        now = int(time.time())
        if self._data:
            if self._data.get("test_token_ttl") is not None:
                if self._data.get("test_token_is_expired"):
                    self._data["_iat"] = now - (2 * self._data["test_token_ttl"])
                    self._data["_exp"] = now - self._data["test_token_ttl"]
                else:
                    self._data["_iat"] = now - (self._data["test_token_ttl"] // 2)
                    self._data["_exp"] = now + (self._data["test_token_ttl"] // 2)
            else:
                self._data["_iat"] = now - 100
                self._data["_exp"] = None
        else:
            self._data["_iat"] = now
            self._data["_exp"] = None

    def set_data(self, data, copy_data: bool = True):
        super().set_data(data, copy_data)
        self._augment_data()


class FakeAuthClientConfig(AuthClientConfig):
    """Fake auth client config for testing"""

    def __init__(
        self,
        token_ttl=None,
        can_login_unattended=False,
        refresh_raises: Exception = None,
        refresh_returns_credential: bool = True,
        login_raises: Exception = None,
        login_returns_credential: bool = True,
        **kwargs,
    ):
        super().__init__(file_path=None, **kwargs)
        self.token_ttl = token_ttl
        self.can_login_unattended = can_login_unattended
        self.refresh_raises = refresh_raises
        self.refresh_returns_credential = refresh_returns_credential
        self.login_raises = login_raises
        self.login_returns_credential = login_returns_credential

    @classmethod
    def meta(cls):
        return {
            "client_type": "fake_test_client",
            "auth_client_class": "FakeAuthClient",
            "display_name": "Fake Test Client",
            "description": "Fake auth client for unit testing",
        }


class FakeAuthClient(AuthClient):
    """Fake auth client with controllable login behavior"""

    def __init__(self, auth_client_config: FakeAuthClientConfig):
        super().__init__(auth_client_config)
        self._fake_client_config = auth_client_config

    def can_login_unattended(self):
        return self._fake_client_config.can_login_unattended

    def login(self, allow_open_browser=False, allow_tty_prompt=False, **kwargs) -> Credential:
        if self._fake_client_config.login_raises:
            raise self._fake_client_config.login_raises
        if not self._fake_client_config.login_returns_credential:
            # This is bad behavior.
            # Clients are supposed to raise if they cannot login.
            return None
        return FakeCredential(self._fake_client_config.token_ttl)

    def refresh(self, refresh_token: str, requested_scopes: List[str]) -> Credential:
        if self._fake_client_config.refresh_raises:
            raise self._fake_client_config.refresh_raises
        if not self._fake_client_config.refresh_returns_credential:
            # This is bad behavior.
            # Clients are supposed to raise if they cannot refresh.
            return None
        return FakeCredential(self._fake_client_config.token_ttl)

    def default_request_authenticator(self, credential):
        """Override required abstract method"""
        raise NotImplementedError("Not needed for these tests")


class FakeRequestAuthenticator(CredentialRequestAuthenticator):
    """Fake request authenticator with controllable state"""

    def __init__(self, credential: FakeCredential, auth_client: FakeAuthClient = None, **kwargs):
        super().__init__(credential=credential, **kwargs)
        self._auth_client = auth_client

    def pre_request_hook(self):
        pass

    def _refresh_needed(self):
        if not self._credential:
            return True
        return self._credential.is_expired()

    def _refresh(self):
        new_credentials = self._auth_client.refresh(refresh_token="dummy", requested_scopes=["test_scope"])
        new_credentials.set_path(self._credential.path())
        new_credentials.set_storage_provider(self._credential.storage_provider())
        new_credentials.save()

        # self.update_credential(new_credential=new_credentials)
        self._credential = new_credentials

    def credential(self, refresh_if_needed: bool = False) -> Optional[Credential]:
        if refresh_if_needed:
            if self._refresh_needed():
                self._refresh()
        return super().credential()


class TestLoginException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class TestRefreshException(AuthException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class AuthTestEnsureAuthenticatorIsReady(unittest.TestCase):
    """Tests for Auth.ensure_request_authenticator_is_ready()"""

    def _create_auth_with_state(
        self,
        has_credential=False,
        is_expired=False,
        token_ttl=200,
        can_login_unattended=False,
        refresh_raises: Exception = None,
        refresh_returns_credential: bool = True,
        login_raises: Exception = None,
        login_returns_credential: bool = True,
    ):
        if has_credential:
            credential = MagicMock(wraps=FakeCredential(token_ttl=token_ttl, is_expired=is_expired))
        else:
            credential = None

        auth_client = MagicMock(
            wraps=FakeAuthClient(
                FakeAuthClientConfig(
                    can_login_unattended=can_login_unattended,
                    token_ttl=token_ttl,
                    refresh_raises=refresh_raises,
                    refresh_returns_credential=refresh_returns_credential,
                    login_raises=login_raises,
                    login_returns_credential=login_returns_credential,
                )
            )
        )

        request_authenticator = MagicMock(
            wraps=FakeRequestAuthenticator(
                credential=credential,
                auth_client=auth_client,
            )
        )

        auth = MagicMock(
            wraps=Auth(
                auth_client=auth_client,
                request_authenticator=request_authenticator,
                token_file_path=None,
                profile_name=None,
            )
        )

        return auth

    # Case #1: Already has valid (non-expired) credential
    def test_case1_has_valid_credential_returns_immediately(self):
        """When credential exists and is not expired, should return without any action"""
        under_test = self._create_auth_with_state(has_credential=True, is_expired=False)

        under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(0, under_test.auth_client().login.call_count)
        self.assertEqual(0, under_test.auth_client().refresh.call_count)

    # Case #2: No credential but can login unattended
    def test_case2_no_credential_can_login_unattended(self):
        """When no credential but can login unattended, should return without login"""
        under_test = self._create_auth_with_state(has_credential=False, can_login_unattended=True)

        under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(0, under_test.auth_client().login.call_count)
        self.assertEqual(0, under_test.auth_client().refresh.call_count)

    # Case #3a: Has expired credential and refresh succeeds
    def test_case3a_expired_credential_refresh_succeeds(self):
        """When credential is expired but refresh succeeds, should refresh without login"""
        under_test = self._create_auth_with_state(
            has_credential=True,
            is_expired=True,
        )

        under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(0, under_test.auth_client().login.call_count)
        self.assertEqual(1, under_test.auth_client().refresh.call_count)

    # Case #3b: Has expired credential and refresh fails
    def test_case3b_expired_credential_refresh_fails_then_login(self):
        """When credential is expired and refresh fails, should fall through to login"""
        under_test = self._create_auth_with_state(
            has_credential=True,
            is_expired=True,
            refresh_raises=Exception("Test Exception - Refresh failed"),
        )

        under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(1, under_test.auth_client().login.call_count)
        self.assertEqual(1, under_test.auth_client().refresh.call_count)

    # Case #3c: Has expired credential and refresh and login fail.
    def test_case3c_expired_credential_refresh_fails_and_login_fails(self):
        """When credential is expired and refresh fails, should fall through to login"""
        test_login_exception = TestLoginException(message="Test Exception - Login failed (3c)")
        test_refresh_exception = TestRefreshException(message="Test Exception - Refresh failed (3c)")
        under_test = self._create_auth_with_state(
            has_credential=True,
            is_expired=True,
            can_login_unattended=False,
            refresh_raises=test_refresh_exception,
            login_raises=test_login_exception,
        )

        with self.assertRaises(TestLoginException) as raised:
            under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(test_login_exception, raised.exception)
        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(1, under_test.auth_client().login.call_count)
        self.assertEqual(1, under_test.auth_client().refresh.call_count)

    # Case #4a: No credential and requires interactive login (succeeds)
    def test_case4a_no_credential_interactive_login_succeeds(self):
        """When no credential and cannot login unattended, should perform interactive login"""
        under_test = self._create_auth_with_state(
            has_credential=False,
            can_login_unattended=False,
        )

        under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(1, under_test.auth_client().login.call_count)
        self.assertEqual(0, under_test.auth_client().refresh.call_count)

    # Case #4b: Interactive login raises an exception.
    def test_case4b_login_fails_with_raise(self):
        """login raises exception that we should see propagated"""
        test_exception = TestLoginException(message="Test Exception - Login failed (4b)")
        under_test = self._create_auth_with_state(
            has_credential=False, can_login_unattended=False, login_raises=test_exception
        )

        with self.assertRaises(TestLoginException) as raised:
            under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(test_exception, raised.exception)
        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(1, under_test.auth_client().login.call_count)
        self.assertEqual(0, under_test.auth_client().refresh.call_count)

    # Case #4c: Interactive login returns None
    def test_case4b_login_returns_none(self):
        """When login returns None, should raise AuthClientContextException"""
        under_test = self._create_auth_with_state(
            has_credential=False,
            can_login_unattended=False,
            login_returns_credential=False,
        )

        expected_exception = AuthClientContextException(
            message="Unknown login failure. No credentials and no error returned."
        )

        with self.assertRaises(AuthClientContextException) as raised:
            under_test.ensure_request_authenticator_is_ready()

        self.assertEqual(str(expected_exception), str(raised.exception))
        self.assertEqual(0, under_test.login.call_count)
        self.assertEqual(1, under_test.auth_client().login.call_count)
        self.assertEqual(0, under_test.auth_client().refresh.call_count)
