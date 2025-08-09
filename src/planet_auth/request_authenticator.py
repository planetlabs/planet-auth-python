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

from abc import abstractmethod, ABC
from typing import Dict, Optional

import httpx
import requests.auth

import planet_auth.logging.auth_logger
from planet_auth.auth_exception import AuthException
from planet_auth.constants import X_PLANET_APP_HEADER, X_PLANET_APP
from planet_auth.credential import Credential

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class RequestAuthenticator(requests.auth.AuthBase, httpx.Auth, ABC):
    """
    Decorate a http request with a bearer auth token.
    """

    def __init__(self, token_body: str = None, token_prefix: str = "Bearer", auth_header: str = "Authorization"):
        # requests.auth.AuthBase.__init__(self)  # Known to be a no-op
        # httpx.Auth.__init__(self)  # Known to be a no-op
        self._token_prefix = token_prefix
        self._token_body = token_body
        self._auth_header = auth_header

    @abstractmethod
    def pre_request_hook(self):
        """
        Hook that will be called immediately prior to making an HTTP request
        so that implementing classes may make preparations.  Derived
        classes are expected to populate the member fields _token_prefix,
        _token_body, and _auth_header with values that are appropriate to
        the specific implementation.  These will then be used during
        subsequent HTTP request to authenticate the connection using
        a beater token authorization HTTP header.

        Implementers may make external network calls as required to perform
        necessary tasks such as refreshing access tokens.

        Implementations should not require user interaction by default. If
        an authentication mechanism will require user interaction, this
        should be an explicit decision that is left to the application
        using the RequestAuthenticator to control.
        """

    def _build_auth_header_payload(self):
        if self._token_prefix:
            # Should we make the space part of the prefix?  What if someone
            # wants no space?
            return self._token_prefix + " " + self._token_body
        else:
            return self._token_body

    def __call__(self, r):
        """
        Decorate a "requests" library based request with authentication
        """
        self.pre_request_hook()
        if self._token_body:
            r.headers[self._auth_header] = self._build_auth_header_payload()
        if X_PLANET_APP_HEADER not in r.headers:
            r.headers[X_PLANET_APP_HEADER] = X_PLANET_APP
        return r

    def auth_flow(self, request: httpx._models.Request):
        """
        Decorate a "httpx" library based request with authentication
        """
        self.pre_request_hook()
        if self._token_body:
            request.headers[self._auth_header] = self._build_auth_header_payload()
        if X_PLANET_APP_HEADER not in request.headers:
            request.headers[X_PLANET_APP_HEADER] = X_PLANET_APP
        yield request


class CredentialRequestAuthenticator(RequestAuthenticator, ABC):
    def __init__(self, credential: Credential = None, **kwargs):
        super().__init__(**kwargs)
        self._credential = credential

    def update_credential(self, new_credential: Credential) -> None:
        """
        Update the request authenticator with a new credential.
        It is the job of a derived class to know how to map the contents
        of a credential into the primitives known to HTTP request
        auth mechanics.  Not all derived classes are expected to
        understand all credential types.
        """
        self._credential = new_credential
        # Clear-out auth material when a new credential is set.
        # child classes are expected to populate it JIT for auth
        # requests.
        self._token_body = None

    def update_credential_data(self, new_credential_data: Dict) -> None:
        """
        Provide raw data that should be used to update the Credential
        object used to authenticate requests.  This information will
        be treated as newer than any file back data associated
        with the credential held by the authenticator, and the file
        will be overwritten.
        """
        if not self._credential:
            # The use cases for this being unset are narrow - mostly in the noop_auth.py module,
            # and the service side client_validator.py.  Neither of these use cases should
            # ever need to call update_credential_data().
            # Should we fail loud, or quiet?  Loud for now.
            raise RuntimeError("Programming error. Cannot update a credential that has has never been set.")

        self._credential.set_data(new_credential_data)
        self._credential.save()  # Clobber old data that may be saved to disk.
        # Clear-out auth material when a new credential is set.
        # child classes are expected to populate it JIT for auth
        # requests.
        self._token_body = None

    def credential(self, refresh_if_needed: bool = False) -> Optional[Credential]:
        """
        Return the current credential.

        This may not be the credential the authenticator was constructed with.
        Request Authenticators are free to refresh credentials depending in the
        needs of the implementation.  This may happen upon this request,
        or may happen as a side effect of RequestAuthenticator operations.
        """
        return self._credential

    def is_initialized(self) -> bool:
        """
        Return true if the CredentialRequestAuthenticator has a credential that
        can be used to make requests.  If a credential is not in memory, storage
        is checked for the existence of a credential, but it will not be loaded
        from storage at this time, preserving JIT loading behavior.
        """
        if self._credential:
            return bool(self._credential.data()) or self._credential.is_persisted_to_storage()
        return False


class SimpleInMemoryRequestAuthenticator(CredentialRequestAuthenticator):
    # This SimpleInMemoryRequestAuthenticator subclasses from
    # CredentialRequestAuthenticator so it can fit in places that
    # is needed. It does not actually know about any Credential
    # types, since how credential types map to the HTTP request
    # authentication fields is credential specific.  This class
    # is more useful for testing and stubbing out interfaces.
    def pre_request_hook(self):
        pass

    def update_credential(self, new_credential: Credential) -> None:
        auth_logger.warning(msg="Generic SimpleInMemoryRequestAuthenticator ignores update_credential()")


class ForbiddenRequestAuthenticator(CredentialRequestAuthenticator):
    def pre_request_hook(self):
        raise AuthException(
            message="Making authenticated requests with the ForbiddenRequestAuthenticator is forbidden."
            " This is most likely the result of a configuration or programming error."
        )
