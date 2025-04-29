# Service Examples
Service examples cover scenarios in which a program wishes to use
the planet auth utilities as a service, verifying the authenticity
of access credentials presented to the service by a client.

It should be noted that Services may also act as clients when making
calls to other services.  When a service is acting in such a capacity,
the [Client Examples](./examples-client.md) apply.
When the service is acting on behalf of itself, it is likely that
a [OAuth2 Client Credentials](./configuration.md#client-credentials-with-client-secret)
configuration applies.

When a service is acting on behalf of one of its clients... 
(TODO: cover this.)

## Verifying OAuth Clients
The [planet_auth.OidcMultiIssuerValidator][] class is provided to assist with
common OAuth client authentication scenarios.  This class can be configured
with a single authority for normal operations, and may optionally be configured
with a secondary authorities.  This allows for complex deployments such as
the seamless migration between auth servers over time.

This utility class may be configured for entirely local token validation,
or may be configured to check token validity against the OAuth token inspection
endpoint.  For most operations, local validation is expected to be used, as
it is more performant, not needing to make blocking network calls, and more
robust, not depending on external service availability.  For high value operations,
remote validation may be performed which checks whether the specific access
token has been revoked.

Tokens are normally not long-lived. Token lifespans should be selected to
strike a balance between security concerns and allow frequent use of local
validation, and not overburden the token inspection endpoint.

Checking tokens against the OAuth token inspection endpoint does require the
use of OAuth clients that are authorized to use the endpoint, and may not
be available to anonymous clients, depending on the auth server configuration.

### Local Access Token Validation
```python linenums="1" title="Basic usage of OidcMultiIssuerValidator. Validate access tokens locally."
{% include 'service/flask--oidc-multi-issuer--local-only-validation.py' %}
```

### Local and Remote Access Token Validation
```python linenums="1" title="Advanced usage of OidcMultiIssuerValidator. Validate access tokens against OAuth inspection endpoints using custom auth clients."
{% include 'service/flask--oidc-multi-issuer--local-and-remote-validation.py' %}
```

## Verifying Planet Legacy Client
This is not supported by this library.
