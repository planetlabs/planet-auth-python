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
# The Planet Authentication Package : `planet_auth`

This package contains functionality for authenticating clients to the
service and managing authentication material.  This package knows nothing
about the application services apart from how to interact with authentication
layers.

This package understands multiple authentication mechanisms, whose details
are encapsulated in implementation subclasses that implement the primary
(mostly abstract) base class interfaces.

With many different ways to interact with authentication services and
ways to use the resulting authorization material (OAuth tokens,
API keys, etc), configuration is important to understand.
See the documentation for [configuration](../configuration).

The primary interfaces implemented for users of this package are as follows:

- [planet_auth.Auth][] - A container class for initializing and grouping
      a working set of authentication objects.
- [planet_auth.AuthClient][] & [planet_auth.AuthClientConfig][] - Responsible for
      interacting with authentication services to obtain a credential that
      may be used with other API requests. Different clients have different
      configuration needs, so a configuration type exists for each client
      type to keep configuration on rails.
- [planet_auth.Credential][] - Models just a credential.  A credential
      is the unit of authorization material that is obtained from an
      authorization service, and provided to an applicaiton service so
      so that the client may make authenticated applicaiton requests.
      This class is responsible for reading and writing saved credentials
      to storage and performing basic data validation.  This class knows
      nothing about how to get a credential or how to use a credential.
- [planet_auth.RequestAuthenticator][] - Responsible for
      decorating application API requests with a credential. Compatible with
      `httpx` and `requests` libraries.  Some authentication mechanisms require
      that the request authenticator also have an
      [AuthClient][planet_auth.AuthClient], others do not.  Whether or not
      this is required is driven by the specifics of the authentication
      mechanism.  It is because of this relationship between credentials,
      auth clients, and request authenticators that the [planet_auth.Auth][]
      class exists.
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
    ClientCredentialsAuthClientBase,
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

from .storage_utils import (
    FileBackedJsonObject,
    FileBackedJsonObjectException,
    InvalidDataException,
    ObjectStorageProvider,
    ObjectStorageProvider_KeyType,
)

__all__ = [
    # Classes
    "Auth",
    "AuthClient",
    "AuthClientConfig",
    "AuthCodeAuthClient",
    "AuthCodeClientConfig",
    "AuthCodeWithClientSecretAuthClient",
    "AuthCodeWithClientSecretClientConfig",
    "AuthCodeWithPubKeyAuthClient",
    "AuthCodeWithPubKeyClientConfig",
    "AuthCodeAuthClientException",
    "AuthException",
    "ClientCredentialsAuthClientBase",
    "ClientCredentialsClientSecretAuthClient",
    "ClientCredentialsClientSecretClientConfig",
    "ClientCredentialsPubKeyAuthClient",
    "ClientCredentialsPubKeyClientConfig",
    "CredentialRequestAuthenticator",
    "DeviceCodeClientConfig",
    "DeviceCodeAuthClient",
    "DeviceCodeWithClientSecretClientConfig",
    "DeviceCodeWithClientSecretAuthClient",
    "DeviceCodeWithPubKeyClientConfig",
    "DeviceCodeWithPubKeyAuthClient",
    "DeviceCodeAuthClientException",
    "Credential",
    "ExpiredTokenException",
    "FileBackedJsonObject",
    "FileBackedJsonObjectException",
    "FileBackedApiKey",
    "FileBackedApiKeyRequestAuthenticator",
    "FileBackedOidcCredential",
    "FileBackedPlanetLegacyApiKey",
    "InvalidAlgorithmTokenException",
    "InvalidDataException",
    "InvalidArgumentException",
    "InvalidTokenException",
    "ObjectStorageProvider",
    "ObjectStorageProvider_KeyType",
    "OidcAuthClient",
    "OidcAuthClientConfig",
    "OidcClientValidatorAuthClientConfig",
    "OidcClientValidatorAuthClient",
    "OidcMultiIssuerValidator",
    "NoOpAuthClient",
    "NoOpAuthClientConfig",
    "PlanetLegacyAuthClient",
    "PlanetLegacyAuthClientConfig",
    "PlanetLegacyRequestAuthenticator",
    "RefreshOrReloginOidcTokenRequestAuthenticator",
    "RefreshingOidcTokenRequestAuthenticator",
    "RequestAuthenticator",
    "ResourceOwnerAuthClient",
    "ResourceOwnerClientConfig",
    "ResourceOwnerWithClientSecretAuthClient",
    "ResourceOwnerWithClientSecretClientConfig",
    "ResourceOwnerWithPubKeyAuthClient",
    "ResourceOwnerWithPubKeyClientConfig",
    "ResourceOwnerAuthClientException",
    "ScopeNotGrantedTokenException",
    "StaticApiKeyAuthClient",
    "StaticApiKeyAuthClientConfig",
    "StaticApiKeyAuthClientException",
    "TokenValidator",
    "TokenValidatorException",
    "UnknownSigningKeyTokenException",
    # Functions
    "setPyLoggerForAuthLogger",
    "setStringLogging",
    "setStructuredLogging",
]
