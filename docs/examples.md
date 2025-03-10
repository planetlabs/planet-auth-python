# Examples

## Installation
Install the required modules:
```shell
pip install planet-auth
```

## Embedding the `plauth` Command in Another `click` Program
It is possible to embed the [`plauth`](/cli-plauth) command into other programs to
present a unified experience that leverages the [planet_auth](/api)
package for client authentication plumbing.  This is done by using
a special version of the command that is configured for embedding.

When using the embedded version of the command, the outer application
must take on the responsibility of instantiating the auth context and
handling command line options so that this context may be available
to click commands that are outside the `plauth` root command.

```python linenums="1"
{% include 'cli/embed-plauth-click.py' %}
```

## Client Examples
Client examples cover scenarios in which a program wishes to use
the planet auth utilities as a client, obtaining credentials
from authentication services so that they may be used to
make authenticated requests to other network services.


### Planet Legacy Authentication

#### Initial Login
```python linenums="1"
{% include 'auth-client/planet-legacy/perform-legacy-initial-login.py' %}
```

#### Authenticated `requests` Call
```python linenums="1"
{% include 'auth-client/planet-legacy/make-legacy-authenticated-requests-request.py' %}
```

### OAuth Client Authentication
It is possible to specify a fully customized auth client profile.
See [Configuration and Profiles](/configuration) for more information 
on client types and profiles.

1. Create a `~/.planet/<profile_name>/auth_client.json` or `~/.planet/<profile_name>/auth_client.sops.json` file.
For example, to create a custom profile named "my-custom-profile", create the following:
```json linenums="1" title="~/.planet/my-custom-profile/auth_client.json"
{% include 'auth-client-config/oauth-auth-code-grant-public-client.json' %}
```
2. Initialize the client library with the specified profile.  Note: if the environment variable
`PL_AUTH_PROFILE` is set, it will be detected automatically by [planet_auth_utils.PlanetAuthFactory][],
and it will not be necessary to explicitly pass in the profile name:
```python linenums="1"
{% include 'auth-client/oauth/initialize-client-lib-on-disk-profile.py' %}
```
An alternative to creating a file on disk is to initialize_from_profile a client
purely in memory.  For some runtime environments where local storage may
not be available or trusted, this may be more appropriate:
```python linenums="1"
{% include 'auth-client/oauth/initialize-client-lib-in-memory.py' %}
```
3. Perform initial login to obtain and save long term credentials, if required
by the configured profile.  An initial login is usually required for auth
clients that act on behalf of a user and need to perform an interactive login.
Clients configured for service operation may frequently skip this step:
```python linenums="1"
{% include 'auth-client/oauth/perform-oauth-initial-login.py' %}
```
4a. Make authenticated requests using `requests`:
```python linenums="1"
{% include 'auth-client/oauth/make-oauth-authenticated-requests-request.py' %}
```

4b. Make authenticated requests using `httpx`:
```python linenums="1"
{% include 'auth-client/oauth/make-oauth-authenticated-httpx-request.py' %}
```

### Performing a Device Login
The procedure for performing initial user login on a UI limited device
is slightly different.  Rather than simply calling `login()`, it is necessary
to initiate the process with a call to `device_login_initiate()`, display the
returned information to the user so that they may authorize the client
asynchronously, and complete the process by calling `device_login_complete()`.
This procedure only applies to clients that are permitted to use the
Device Authorization OAuth flow.

```python linenums="1"
{% include 'auth-client/oauth/perform-oauth-device-login.py' %}
```

## Service Examples
Service examples cover scenarios in which a program wishes to use
the planet auth utilities as a service, verifying the authenticity
of access credentials presented to the service by a client.

It should be noted that Services may also act as clients when making
calls to other services.  When the service is acting on behalf
of itself, that case is covered by the examples above.

When a service is acting on behalf of one of its clients... 
(TODO: cover this.)

### Verifying OAuth Clients
The [planet_auth.OidcMultiIssuerValidator][] class is provided to assist with
common OAuth client authentication scenarios.  This class can be configured
with a single authority for normal operations, and may optionally be configured
with a secondary authority.

Configuration of a secondary token issuer is not expected to be a normal
mode of operation, but was developed to support deployments during migrations
between authorities. The utility will log a warning when the secondary authority
is accepted.

This utility class may be configured for entirely local token validation,
or may be configured to check token validity against the OAuth token inspection
endpoint.  For most operations, local validation is expected to be used, as
it is more performant, not needing to make blocking network calls, and more
robust, not depending on external service availability.  For high value operations,
remote validation may be performed, which checks whether the specific access
token has been revoked.

Tokens are normally not long-lived. Token lifespans should be selected to
strike a balance between security concerns and allow frequent use of local
validation, and not overburden the token inspection endpoint.

Checking tokens against the OAuth token inspection endpoint does require the
use of OAuth clients that are authorized to use the endpoint, and may not
be available to anonymous clients, depending on the auth server configuration.

#### Local Access Token Validation
```python linenums="1" title="Basic usage of OidcMultiIssuerValidator. Validate access tokens locally."
{% include 'service/flask--oidc-multi-issuer--local-only-validation.py' %}
```

#### Local and Remote Access Token Validation
```python linenums="1" title="Advanced usage of OidcMultiIssuerValidator. Validate access tokens against OAuth inspection endpoints using custom auth clients."
{% include 'service/flask--oidc-multi-issuer--local-and-remote-validation.py' %}
```

### Verifying Planet Legacy Client
This is not supported by this library.
