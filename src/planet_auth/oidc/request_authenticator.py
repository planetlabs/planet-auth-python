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

import jwt
import time
from typing import Dict, Optional

import planet_auth.logging.auth_logger
from planet_auth.credential import Credential
from planet_auth.request_authenticator import CredentialRequestAuthenticator
from planet_auth.oidc.auth_client import OidcAuthClient
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


# Note: Auth client can be passed override scopes for token refresh, but we
#       haven't plumbed our auth helpers to do this. This is probably an
#       acceptable limitation for this use case.
# Note: We assume the caller knows what they are doing. It might be
#       nice to warn (or fail) if we detect that there is a mismatch between
#       the destination this authenticator is providing tokens to and the
#       audience of the token.  That is beyond basic OAuth, since
#       1) tokens need not be transparent or JWTs, and
#       2) the audience need not be a URL we understand.
#       The risk is in handing out access tokens to a destination
#       that we do not trust.
class RefreshingOidcTokenRequestAuthenticator(CredentialRequestAuthenticator):
    """
    Decorate a http request with an OAuth bearer auth token. Automatically
    initiate a refresh request if we know the access token to be close to
    expiration.

    This class assumes access tokens are JWTs and can be locally inspected,
    which OIDC and OAuth do not require.  JWT access tokens that comply with
    RFC 9068 can be checked for expiration timing without hitting the network
    token introspection endpoint.
    """

    def __init__(self, credential: FileBackedOidcCredential, auth_client: OidcAuthClient = None, **kwargs):
        super().__init__(credential=credential, **kwargs)
        self._auth_client = auth_client
        self._refresh_at = 0

    def _load(self):
        if self._credential.path():
            # allow in memory operation.
            self._credential.load()

        access_token_str = self._credential.access_token()
        # Absolutely not appropriate to not verify the signature in a token
        # validation context (e.g. server side auth of a client). Here we
        # know that's not what we are doing. This is a client helper class
        # for clients who will be presenting tokens to such a server.  We
        # are inspecting ourselves, not verifying for trust purposes.
        # We are not expected to be the audience.
        # TODO: we should use `expires_in` from the response from the
        #    OAuth server, which would work for non-JWT opaque OAuth
        #    tokens.  Since that is a relative time, we would also need
        #    to augment our FileBackedOidcCredential with an issued
        #    at time.
        unverified_decoded_atoken = jwt.decode(access_token_str, options={"verify_signature": False})  # nosemgrep
        iat = unverified_decoded_atoken.get("iat") or 0
        exp = unverified_decoded_atoken.get("exp") or 0
        # refresh at the 3/4 life
        self._refresh_at = int(iat + (3 * (exp - iat) / 4))
        self._token_body = access_token_str

    def _refresh(self):
        if self._auth_client:
            # TODO: cleanup?  We did this before we wrote "update_credential_data()"
            #    We maybe should just be using that now.  Taking that clean-up slow
            #    since it may have interactions with derived code.
            #    It seems to me we should be able to collapse the credential.save()
            #    calls in this file with the superclass.
            new_credentials = self._auth_client.refresh(self._credential.refresh_token())
            new_credentials.set_path(self._credential.path())
            new_credentials.set_storage_provider(self._credential.storage_provider())
            new_credentials.save()

            # self.update_credential(new_credential=new_credentials)
            self._credential = new_credentials
            self._load()

    def _refresh_if_needed(self):
        # Reload the file before refreshing. Another process might
        # have done it for us, and save us the network call.
        #
        # Also, if refresh tokens are configured to be one time use,
        # we want a fresh refresh token. Stale refresh tokens may be
        # invalid depending on server configuration.
        #
        # Also, it's possible that we have a valid refresh token,
        # but not an access token.  When that's true, we should
        # try to cash in the refresh token.
        #
        # If everything fails, continue with what we have. Let the API
        # we are calling decide if it's good enough.
        now = int(time.time())
        if now > self._refresh_at:
            try:
                self._load()
            except Exception as e:  # pylint: disable=broad-exception-caught
                auth_logger.warning(
                    msg=f"Error loading auth token. Continuing with old configuration and token data. Load error: {str(e)}"
                )
        if now > self._refresh_at:
            try:
                self._refresh()
            except Exception as e:  # pylint: disable=broad-exception-caught
                auth_logger.warning(
                    msg=f"Error obtaining new or refreshed auth token. Continuing with old configuration and token data. Refresh error: {str(e)}"
                )

        # This tries to give a client a better error when there is no old
        # token to fall back to.  But, it is known to cause problems when
        # auth truly isn't needed, either because the service does not need
        # it or because it has been mocked out (as in unit test cases).
        # So, we rely on the warnings to keep the user informed. This might
        # also result in the user seeing errors from the server - the quality
        # of which we have no control over.
        #
        # if not (self._credential and self._credential.is_loaded()):
        #     # "refresh" may also be called to initialize in some cases, as in client credentials flow.
        #     # Continuing with what we have is not an option when we have nothing.
        #     raise AuthException("Failed to load or obtain a valid access token.")

    def pre_request_hook(self):
        self._refresh_if_needed()
        super().pre_request_hook()

    def update_credential(self, new_credential: Credential) -> None:
        if not isinstance(new_credential, FileBackedOidcCredential):
            raise TypeError(
                f"{type(self).__name__} does not support {type(new_credential)} credentials.  Use FileBackedOidcCredential."
            )
        super().update_credential(new_credential=new_credential)
        self._refresh_at = 0
        # self._load()  # Mimic __init__.  Don't load, let that happen JIT.

    def update_credential_data(self, new_credential_data: Dict) -> None:
        # This is more different than update_credential() than it may
        # appear. Inherent in being passed a Credential in update_credential()
        # is that it may not yet be loaded from disk, and so deferring
        # the _load() as a JIT operation is appropriate.  In this case,
        # being passed the data struct is as if a network refresh call
        # has already taken place or a _load() is in progress, and we
        # should behave as  if we are finishing a _refresh() call.
        super().update_credential_data(new_credential_data=new_credential_data)
        self._load()

    def credential(self, refresh_if_needed: bool = False) -> Optional[Credential]:
        if refresh_if_needed:
            self._refresh_if_needed()
        return super().credential()


class RefreshOrReloginOidcTokenRequestAuthenticator(RefreshingOidcTokenRequestAuthenticator):
    """
    Decorate a http request with a bearer auth token. Automatically initiate
    a refresh request using the refresh token if we know the access token to
    be close to expiration. If we do not have a refresh token, then fall back
    to re-initiating a login.  Sometimes (like with client credential flow),
    refresh tokens may not be available and we might want to login rather
    than refresh.  It is not an automatic choice to fall back to login when
    refresh is not available, since for some auth client configurations login
    is interactive, and would not be appropriate for headless use cases.
    Refresh should always be silent.
    """

    def __init__(self, credential: FileBackedOidcCredential, auth_client: OidcAuthClient = None, **kwargs):
        super().__init__(credential=credential, auth_client=auth_client, **kwargs)

    def _refresh(self):
        if self._auth_client:
            try:
                _refresh_token = self._credential.refresh_token()
            except FileNotFoundError:
                # Token file might not exist in the "or (re)login" case.
                _refresh_token = None

            if _refresh_token:
                new_credentials = self._auth_client.refresh(_refresh_token)
            else:
                new_credentials = self._auth_client.login(allow_open_browser=False, allow_tty_prompt=False)

            new_credentials.set_path(self._credential.path())
            new_credentials.set_storage_provider(self._credential.storage_provider())
            new_credentials.save()

            # self.update_credential(new_credential=new_credentials)
            self._credential = new_credentials
            self._load()
