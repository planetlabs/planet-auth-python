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
from abc import ABC
from typing import Union

from planet_auth.credential import Credential
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.request_authenticator import (
    RefreshOrReloginOidcTokenRequestAuthenticator,
    RefreshingOidcTokenRequestAuthenticator,
)
from planet_auth.oidc.auth_client import OidcAuthClient


def _common_prepare_oidc_credential(self: OidcAuthClient, credential: Union[pathlib.Path, Credential]):
    storage_provider = self._auth_client_config.storage_provider()
    if isinstance(credential, pathlib.Path):
        _credential = FileBackedOidcCredential(credential_file=credential, storage_provider=storage_provider)
    elif isinstance(credential, FileBackedOidcCredential):
        _credential = credential
    elif credential is None:
        # An empty, path-less (in memory) credential to start the request authenticator off with.
        # Authenticators are permitted to obtain credentials JIT. (E.g. Client Credentials Grant.)
        # Otherwise, the request authenticator will be brain-dead until update_credential()
        # or update_credential_data() is called.  This is still useful for initializing properly
        # typed credential objects.
        _credential = FileBackedOidcCredential(storage_provider=storage_provider)
    else:
        raise TypeError(
            f"{type(self).__name__} does not support {type(credential)} credentials.  Use file path or FileBackedOidcCredential."
        )
    return _credential


class OidcAuthClientWithRefreshOrReloginOidcTokenRequestAuthenticator(ABC):
    """
    Mix-in base class for flows that should default to the
    RefreshOrReloginOidcTokenRequestAuthenticator request authenticator.
    """

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> RefreshOrReloginOidcTokenRequestAuthenticator:
        _credential = _common_prepare_oidc_credential(self, credential)  # type: ignore
        return RefreshOrReloginOidcTokenRequestAuthenticator(credential=_credential, auth_client=self)  # type: ignore


class OidcAuthClientWithRefreshingOidcTokenRequestAuthenticator(ABC):
    """
    Mix-in base class for flows that should default to the
    RefreshingOidcTokenRequestAuthenticator request authenticator.
    """

    def default_request_authenticator(
        self, credential: Union[pathlib.Path, Credential]
    ) -> RefreshingOidcTokenRequestAuthenticator:
        _credential = _common_prepare_oidc_credential(self, credential)  # type: ignore
        return RefreshingOidcTokenRequestAuthenticator(credential=_credential, auth_client=self)  # type: ignore
