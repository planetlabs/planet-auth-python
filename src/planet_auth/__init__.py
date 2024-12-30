# Copyright 2024 Planet Labs PBC.
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
The Planet Authentication package

This package contains functionality for authenticating clients to the
service and managing authentication material.  This package knows nothing
about the service itself apart from how to interact with authentication
APIs.

This package understands multiple authentication mechanisms, whose details
are encapsulated in implementation subclasses that implement the primary
(mostly abstract) base class interfaces.

With many different ways to interact with authentication services and
ways to use the resulting authorization material (OAuth tokens,
API keys, etc), configuration is important to understand.
See the documentation for [configuration](../configuration).

The primary interfaces implemented for users of this package are as follows:

- [planet_auth.Auth][] - A container class for initializing and grouping
      a working set of authentication objects (below).
- [planet_auth.AuthClient][] & [planet_auth.AuthClientConfig][] - Responsible for
      interacting with authentication services to obtain a credential that
      may be used with other API requests. Different clients have different
      configuration needs, so a configuration type exists for each client
      type to keep configuration on rails.
- [planet_auth.Credential][] - Models just a credential.
      Responsible for reading and writing saved credentials to disk and
      performing basic data validation.  Knows nothing about how to get a
      credential, or how to use a credential.
- [planet_auth.RequestAuthenticator][] - Responsible for
      decorating API requests with a credential. Compatible with `httpx` and
      `requests` libraries.  Some authentication mechanisms require that
      the request authenticator also have an
      [AuthClient][planet_auth.AuthClient], others do not.  Whether or not
      this is required is driven by the specifics of the authentication
      mechanism.
"""

from .auth import Auth
from .auth_exception import AuthException
from .auth_client import AuthClientConfig, AuthClient
from .credential import Credential
from .request_authenticator import RequestAuthenticator, CredentialRequestAuthenticator
from .logging.auth_logger import setPyLoggerForAuthLogger, setStringLogging, setStructuredLogging

from .oidc.auth_client import OidcAuthClient, OidcAuthClientConfig
from .oidc.auth_clients.auth_code_flow import (
    AuthCodeClientConfig,
    AuthCodeAuthClient,
    AuthCodeWithClientSecretClientConfig,
    AuthCodeWithClientSecretAuthClient,
    AuthCodeWithPubKeyClientConfig,
    AuthCodeWithPubKeyAuthClient,
    AuthCodeAuthClientException,
)
from .oidc.auth_clients.client_credentials_flow import (
    ClientCredentialsClientSecretClientConfig,
    ClientCredentialsClientSecretAuthClient,
    ClientCredentialsPubKeyClientConfig,
    ClientCredentialsPubKeyAuthClient,
)
from .oidc.auth_clients.device_code_flow import (
    DeviceCodeClientConfig,
    DeviceCodeAuthClient,
    DeviceCodeWithClientSecretClientConfig,
    DeviceCodeWithClientSecretAuthClient,
    DeviceCodeWithPubKeyClientConfig,
    DeviceCodeWithPubKeyAuthClient,
    DeviceCodeAuthClientException,
)
from .oidc.auth_clients.client_validator import (
    OidcClientValidatorAuthClientConfig,
    OidcClientValidatorAuthClient,
)
from .oidc.auth_clients.resource_owner_flow import (
    ResourceOwnerClientConfig,
    ResourceOwnerAuthClient,
    ResourceOwnerWithClientSecretClientConfig,
    ResourceOwnerWithClientSecretAuthClient,
    ResourceOwnerWithPubKeyClientConfig,
    ResourceOwnerWithPubKeyAuthClient,
    ResourceOwnerAuthClientException,
)
from .oidc.token_validator import (
    ExpiredTokenException,
    InvalidAlgorithmTokenException,
    InvalidArgumentException,
    InvalidTokenException,
    ScopeNotGrantedTokenException,
    TokenValidator,
    TokenValidatorException,
    UnknownSigningKeyTokenException,
)
from .oidc.multi_validator import OidcMultiIssuerValidator
from .planet_legacy.auth_client import PlanetLegacyAuthClientConfig, PlanetLegacyAuthClient
from .static_api_key.auth_client import (
    StaticApiKeyAuthClientConfig,
    StaticApiKeyAuthClient,
    StaticApiKeyAuthClientException,
)
from .none.noop_auth import NoOpAuthClientConfig, NoOpAuthClient

from .oidc.oidc_credential import FileBackedOidcCredential
from .planet_legacy.legacy_api_key import FileBackedPlanetLegacyApiKey
from .static_api_key.static_api_key import FileBackedApiKey

from .oidc.request_authenticator import (
    RefreshingOidcTokenRequestAuthenticator,
    RefreshOrReloginOidcTokenRequestAuthenticator,
)
from .planet_legacy.request_authenticator import PlanetLegacyRequestAuthenticator
from .static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator

from .util import InvalidDataException

__all__ = [
    # Classes
    Auth.__name__,
    AuthClient.__name__,
    AuthClientConfig.__name__,
    AuthCodeAuthClient.__name__,
    AuthCodeClientConfig.__name__,
    AuthCodeWithClientSecretAuthClient.__name__,
    AuthCodeWithClientSecretClientConfig.__name__,
    AuthCodeWithPubKeyAuthClient.__name__,
    AuthCodeWithPubKeyClientConfig.__name__,
    AuthCodeAuthClientException.__name__,
    AuthException.__name__,
    ClientCredentialsClientSecretAuthClient.__name__,
    ClientCredentialsClientSecretClientConfig.__name__,
    ClientCredentialsPubKeyAuthClient.__name__,
    ClientCredentialsPubKeyClientConfig.__name__,
    CredentialRequestAuthenticator.__name__,
    DeviceCodeClientConfig.__name__,
    DeviceCodeAuthClient.__name__,
    DeviceCodeWithClientSecretClientConfig.__name__,
    DeviceCodeWithClientSecretAuthClient.__name__,
    DeviceCodeWithPubKeyClientConfig.__name__,
    DeviceCodeWithPubKeyAuthClient.__name__,
    DeviceCodeAuthClientException.__name__,
    Credential.__name__,
    ExpiredTokenException.__name__,
    FileBackedApiKey.__name__,
    FileBackedApiKeyRequestAuthenticator.__name__,
    FileBackedOidcCredential.__name__,
    FileBackedPlanetLegacyApiKey.__name__,
    InvalidAlgorithmTokenException.__name__,
    InvalidDataException.__name__,
    InvalidArgumentException.__name__,
    InvalidTokenException.__name__,
    OidcAuthClient.__name__,
    OidcAuthClientConfig.__name__,
    OidcClientValidatorAuthClientConfig.__name__,
    OidcClientValidatorAuthClient.__name__,
    OidcMultiIssuerValidator.__name__,
    NoOpAuthClient.__name__,
    NoOpAuthClientConfig.__name__,
    PlanetLegacyAuthClient.__name__,
    PlanetLegacyAuthClientConfig.__name__,
    PlanetLegacyRequestAuthenticator.__name__,
    RefreshOrReloginOidcTokenRequestAuthenticator.__name__,
    RefreshingOidcTokenRequestAuthenticator.__name__,
    RequestAuthenticator.__name__,
    ResourceOwnerAuthClient.__name__,
    ResourceOwnerClientConfig.__name__,
    ResourceOwnerWithClientSecretAuthClient.__name__,
    ResourceOwnerWithClientSecretClientConfig.__name__,
    ResourceOwnerWithPubKeyAuthClient.__name__,
    ResourceOwnerWithPubKeyClientConfig.__name__,
    ResourceOwnerAuthClientException.__name__,
    ScopeNotGrantedTokenException.__name__,
    StaticApiKeyAuthClient.__name__,
    StaticApiKeyAuthClientConfig.__name__,
    StaticApiKeyAuthClientException.__name__,
    TokenValidator.__name__,
    TokenValidatorException.__name__,
    UnknownSigningKeyTokenException.__name__,
    # Functions
    setPyLoggerForAuthLogger.__name__,
    setStringLogging.__name__,
    setStructuredLogging.__name__,
]
