# Client Examples
Client examples cover scenarios in which a program wishes to use
the planet auth utilities as a client, obtaining credentials
from authentication services so that they may be used to
make authenticated requests to other network services.

## OAuth Client Authentication
A custom auth client profile may be used to configure the AuthClient
to use an arbitrary OAuth2 auth service to obtain access tokens for
use with application APIs.
See [Configuration and Profiles](./configuration.md) for more information
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
4. Make authenticated requests:
    * Option 1 - Using `requests`:
```python linenums="1"
{% include 'auth-client/oauth/make-oauth-authenticated-requests-request.py' %}
```
    * Option 2 - Using `httpx`:
```python linenums="1"
{% include 'auth-client/oauth/make-oauth-authenticated-httpx-request.py' %}
```

## Performing a Device Login
The procedure for performing initial user login on a UI limited device
is slightly different.  Rather than simply calling `login()`, it is necessary
to initiate the process with a call to `device_login_initiate()`, display the
returned information to the user so that the user may authorize the client
asynchronously, and complete the process by calling `device_login_complete()`.
This procedure only applies to clients that are permitted to use the
Device Authorization OAuth flow.

```python linenums="1"
{% include 'auth-client/oauth/perform-oauth-device-login.py' %}
```

## Planet Legacy Authentication
The proprietary Planet legacy authentication protocol is targeted for future
deprecation.  It should not be used for any new development.

### Initial Login
```python linenums="1"
{% include 'auth-client/planet-legacy/perform-legacy-initial-login.py' %}
```

### Authenticated `requests` Call
```python linenums="1"
{% include 'auth-client/planet-legacy/make-legacy-authenticated-requests-request.py' %}
```
