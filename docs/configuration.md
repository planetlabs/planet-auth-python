# Configuration and Profiles

## Auth Clients
The AuthClient is responsible for all interactions with the authentication
services.  How a client interacts with the authentication services can vary
considerably between implementations.

AuthClient Configuration dictionaries may either be provided directly, or loaded
from disk when saved in a `Profile` (See below).

While it is possible to work directly with the lower level implementation
classes, it is generally simpler to organize the working set of objects
with an [Auth Context][planet_auth.Auth] instance created from one of the
factory methods in [planet_auth_utils.PlanetAuthFactory][]

A number of auth client implementations are provided.  Clients should
select the one most appropriate for their use case.

### OAuth Clients
#### Auth Code with PKCE
Implemented by [planet_auth.AuthCodeAuthClient][] and [planet_auth.AuthCodeClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-auth-code-grant-public-client.json' %}
```

Profile Usage:
```python linenums="1"
{% include 'snippets/auth-client-context-from-saved-profile.py' %}
```

Direct Usage:
```python linenums="1"
{% include 'snippets/auth-client-context-oauth-direct.py' %}
```

#### Auth Code with PKCE and Client Public Key
Implemented by [planet_auth.AuthCodeWithPubKeyAuthClient][] and [planet_auth.AuthCodeWithPubKeyClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-auth-code-grant-confidential-client-pubkey.json' %}
```
Only one of `client_privkey` or `client_privkey_file` is required.

Profile Usage and Direct Usage as shown above.

#### Auth Code with PKCE and Client Secret
Implemented by [planet_auth.AuthCodeWithClientSecretAuthClient][] and [planet_auth.AuthCodeWithClientSecretClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-auth-code-grant-confidential-client-secret.json' %}
```

Profile Usage and Direct Usage as shown above.

#### Client Credentials with Client Public Key
Implemented by [planet_auth.ClientCredentialsPubKeyAuthClient][] and [planet_auth.ClientCredentialsPubKeyClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-client-credentials-grant-confidential-client-pubkey.json' %}
```
Only one of `client_privkey` or `client_privkey_file` is required.

Profile Usage and Direct Usage as shown above.

#### Client Credentials with Client Secret
Implemented by [planet_auth.ClientCredentialsClientSecretAuthClient][] and [planet_auth.ClientCredentialsClientSecretClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-client-credentials-grant-confidential-client-secret.json' %}
```

Profile Usage and Direct Usage as shown above.

#### Resource Owner
!!! Warning "Insecure Practice"
Use of this OAuth client type is discouraged.

Implemented by [planet_auth.ResourceOwnerAuthClient][] and [planet_auth.ResourceOwnerClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-password-grant-public-client.json' %}
```

Profile Usage and Direct Usage as shown above.

#### Resource Owner with Client Public Key
!!! Warning "Insecure Practice"
Use of this OAuth client type is discouraged.

Implemented by [planet_auth.ResourceOwnerWithPubKeyAuthClient][] and [planet_auth.ResourceOwnerWithPubKeyClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-password-grant-confidential-client-pubkey.json' %}
```
Only one of `client_privkey` or `client_privkey_file` is required.

Profile Usage and Direct Usage as shown above.

#### Resource Owner with Client Secret
!!! Warning "Insecure Practice"
Use of this OAuth client type is discouraged.

Implemented by [planet_auth.ResourceOwnerWithClientSecretAuthClient][] and [planet_auth.ResourceOwnerWithClientSecretClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-password-grant-confidential-client-secret.json' %}
```

Profile Usage and Direct Usage as shown above.

#### OAuth2/OIDC Client Validator
Implemented by [planet_auth.OidcClientValidatorAuthClient][] and [planet_auth.OidcClientValidatorAuthClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/oauth-client-validator.json' %}
```

Usage of this configuration is different from most.  This configuration
does not prepare an Auth context that is suitable for making authenticated
outbound calls, which is one of the primary aims of most auth client types.
Instead, this client configuration can only be used to validate incoming
tokens.

### Planet Legacy Client
Implemented by [planet_auth.PlanetLegacyAuthClient][] and [planet_auth.PlanetLegacyAuthClientConfig][]

Configuration:
```json linenums="1" title="~/.planet/_profile_name_/auth_client.json"
{% include 'auth-client-config/planet-legacy.json' %}
```

Profile Usage:
```python linenums="1"
{% include 'snippets/auth-client-context-from-saved-profile.py' %}
```


Direct Usage:
```python linenums="1"
{% include 'snippets/auth-client-context-pl-legacy-direct.py' %}
```

## Environment Variables
See [planet_auth_utils.EnvironmentVariables][] for a list of environment variables.

## On Disk Configuration Profiles

Central to how the auth client library manages on disk configuration
is the concept of an auth profile.  The auth profile specifies an
AuthClient configuration, controlling how the library interacts with
authentication services to obtain service tokens. The AuthClient
configuration also controls how those tokens are subsequently used to
interact with other services.  Auth profiles may be used to manage
different user accounts by creating multiple named profiles with
otherwise identical AuthClient configurations.

The auth profile also determines where authentication configuration
files and authentication tokens are stored on disk.  When a given
profile is selected, the `~/.planet/<profile>` directory will be used in
the user’s home directory.  Profile names will be down-cased to
all lowercase. Within the currently active profile directory, auth
credentials will be stored in a `token.json` file, and auth profile
configuration will be stored in an `auth_client.json` file.  The contents
and format of these files vary depending on the specific auth mechanism
configured for the auth profile.  If present, `auth_client.sops.json`
will take priority over `auth_client.json`, allowing clients that have
secrets to securely store this information on disk using SOPS encryption.
Similarly, a `token.sops.json` file will take priority over a `token.json`
file. The configuration of SOPS is outside the scope of this tooling, and
left to the user.
