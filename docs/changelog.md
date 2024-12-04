# Changelog

## [Unreleased:2.0.0] - YYYY-MM-DD
- 2.0.X is a development series, not intended for production. When ready,
  the version will be bumped beyond 2.1.
- Prepare for public release and Python SDK integration. See [`planet-client-python`](https://github.com/planetlabs/planet-client-python).
- Add support for device code authorization client type and flows.
- Rename Auth Code flow classes to omit `PKCE` from their name.
  PKCE is not an intrinsic part of the flow, only a best practice security
  addition.
  - On upgrading from 1.X.X -> 2.0.0, users will need to accommodate this class
    renaming.  The interfaces are otherwise unchanged between 1.X.X and 2.0.0,
    and no change has been made to on disk formats of client configurations.
    - `AuthCodePKCEClientConfig` -> `AuthCodeClientConfig`
    - `AuthCodePKCEAuthClient` -> `AuthCodeAuthClient`
    - `AuthCodePKCEWithClientSecretClientConfig` -> `AuthCodeWithClientSecretClientConfig`
    - `AuthCodePKCEWithClientSecretAuthClient` -> `AuthCodeWithClientSecretAuthClient`
    - `AuthCodePKCEWithPubKeyClientConfig` -> `AuthCodeWithPubKeyClientConfig`
    - `AuthCodePKCEWithPubKeyAuthClient` -> `AuthCodeWithPubKeyAuthClient`
- Initialization methods in the `Auth` class have been revamped.
  Application user-friendly initialization helpers now live in the `planet-auth-utils` library.
- Auth.initialize_from_env has been deprecated. Use `planet-auth-utils` library options.
- Auth.initialize_from_profile has been deprecated. Use `planet-auth-utils` library options.
- The `Profile` class has been removed from this library and included in the companion `planet-auth-utils` library.
- Added `extra` as keyword parameter providing a generic way to pass deployment
  specific extra parameters to an OAuth request. (Such as Auth0's `organization` selection.)
  The `extra` keyword argument takes a dict that will be appended to authentication
  and authorization requests.
- `organization`, which is an Auth0 extension, has been removed from keyword parameters
  of methods such as `login` that used it. Use the newly added `extra` keyword
  that take a map to pass deployment specific parameters to an OAuth request.
- `OidcMultiIssuerValidator` has been simplified:
  - The concept of separate "primary" and "secondary" has been removed, flattening
    trust structure. Logging was the only material difference, and this is better
    handled external to the library in ways specific to the use case.
  - This change has two parts:
    - The initialization parameters `secondaries` and `log_secondary` have been removed.
    - The initialization parameters `primaries` and `log_primary` have been
      renamed to `trusted` and `log_result`, respectively.
- Python version floor raised to 3.9
- Added pyflakes, mypy, and pylint linting. Fixes from the linting.
- TODO: planet-auth-utils has been merged into this distribution package.
- Environment variable constants consolidated under `planet_auth_utils`

- TODO: before main release, reconsider what packages should be public,
  and which should be .internal packages. 
- TODO: Exclude internal packages from pydocs
- TODO: refactor documentation to only cover public functions (or, at least
  generate the docs separately for internal functions.)
- TODO: migrate from unittest -> pytest?
- TODO: audit where I am doing "# type: ignore" and make fixes.
- TODO: audit where I am doing "# pylint: disable" and make fixes.
- TODO: Add tests to mypy
- TODO: support env vars for WORKSPACE and PROJECT.  (Both for core lib, and for the CLI.)
- TODO: Refactors "Auth Enricher" to use authenticator interface if possible. As a follow-up,
        we should also remove unnecessary params like "client_id" from api client methods
        and flow methods where it is not needed.
- TODO: clean up base authClient classes.  Much of that is OIDC specific.
- TODO: most low level API clients have all args as mandatory. 
        Token API client does not. We should unify convention.
- TODO: low level API client methods largely do not have type hinting. Fix this.
- TODO: update documentation and examples
- TODO: Add SAST/DAST scanning to build apart from what the security group does.
- TODO: The refreshing request authenticator should record refresh time from the OAuth
        server response over the token inspection. Tokens may be opaque.
- TODO: Fix mkdocs warnings, make warnings fatal.

## 1.5.1 - 2024-04-15
- Add additional library information to logs.

## 1.5.0 - 2024-01-16
- Adding support for `userinfo` endpoint.

## 1.4.4 - 2024-01-09
- Better handling of discovery indicating that an OAuth server does not
  support particular endpoints.

## 1.4.3 - 2023-12-20
- Change the UnknownSigningKeyTokenException to be available to
  import from top level for exception handling of
  `TokenValidator.validate_token()`.

## 1.4.2 - 2023-10-27
- Change handling of unknown / unsupported key algorithms from the jwks
  endpoint.  You will still have a bad day if you expect such tokens
  to work, but if jwks advertise unsupported keys that are incidental
  to the needs of the application, it should be a warning and not a
  failure.
- Make what algorithms are trusted configurable in the lower level
 `TokenValidator` class.  The higher level `OidcMultiIssuerValidator`
  does not yet expose this ability.

## 1.4.1 - 2023-10-17
- Fix exception wrapping in `OidcMultiIssuerValidator`

## 1.4.0 - 2023-10-17
- Support for Python 3.12
- Add `nested_key` option to `setStructuredLogging` to allow apps to
  enable or disable the logging of attributes in a nested dictionary. The
  default is currently `props` which supports apps (e.g. pda-admin) using the
  `json_logging` module. Apps that don't want nesting can disable it by using
  `nested_key=None`.

## 1.3.2 - 2023-09-28
- Updated examples and documentation.
- Bugfix: Confidential clients were not authenticating when using a refresh
  token. This has been fixed.

## 1.3.1 - 2023-09-25
- A few small changes to support the needs of Planet internal developers:
  - Made the static helper method `prep_pkce_auth_payload` public on the low
    level `AuthorizationApiClient` class.  This allows this class to be
    used as a helper in applications that are not utilizing all of the
    higher level functions of the library.  Use with caution, since
    this was not the primary use case the library was developed for.
  - Make the low level API clients initialized under `OidcAuthClient`
    non-private, so they may be leveraged in off-label use as helpers.
    Using the lower level clients in this way should be done with caution,
    since it removes the context the higher level `OidcAuthClient` provides.
    Most notably, when the client is a confidential client, the handling
    of client authentication will be lost.

## 1.3.0 - (Unstable development release)
- Unstable development release

## 1.2.14 - 2023-09-22
- Log the scope claims seen in access tokens

## 1.2.13 - 2023-09-11
- Hush logging of the "sub" token field.  For better or worse, this contains user email
  addresses at Planet, which might be considered PII.  Log the pl_principal claim instead.

## 1.2.12 - 2023-09-08
- Add the ability to log either using a structured json object, or as a string.
- Documentation and example improvements.

## 1.2.7 - 1.2.11 - (Unstable development releases)
- Unstable development versions.

## 1.2.6 - 2023-09-07 (Retracted)
- This release was retracted.

## 1.2.5 - 2023-09-07
- More unit tests.

## 1.2.4 - 2023-09-06
- Update example in the docs.

## 1.2.3 - 2023-09-02
- Change the default to log the validation of tokens from primary (non-deprecared) issuers.
- Fix a bug where when primary validation was disabled, logging would still happen, and happen
  incorrectly as "warning" and as a deprecated issuer.

## 1.2.2 - 2023-08-29
- Allow the py logger to be set to None to quiet logging entirely.

## 1.2.1 - 2023-08-25
- Changes to logging format to support dashboard. Logs now are structured json with an enumerated
  event type to facilitate dashboards from logs.
- Refactor all logging to use the wrapper class AuthLogger
- Exceptions have been refactored to improve hierarchy, and allow for more bundling of data.

## 1.2.0
- _Internal Development Version_

## 1.1.0 - 2023-08-15
- Add support for authenticating to a specific organization.
  This is supported by Auth0's authorization servers.

## 1.0.0 - 2023-08-02
- Align log messages with the parallel GoLang library so that they may feed a common dashboard.
- It's time to call this lib released, and leave "version 0" behind.
- Minor documentation fixes.

## 0.9.0 - 2023-07-19
- Remove dependency on constants defining specific environments from core library code.
  This has a number of implications:
  - Built-in profiles are no longer a property of the core library. The job of deciding
    default behavior is left to the application.  This manifests in
    [Auth.initialize_from_profile][planet_auth.Auth.initialize_from_profile]
    and [Profile][planet_auth.Profile] factory methods
    no longer understanding the previously understood profiles `default`, `staging`,
    `legacy`, or `none`.
  - Handling of initialization from environment variables is no longer implicit.
    Applications wishing to initialize from environment variables should explicitly call
    [Auth.initialize_from_env][planet_auth.Auth.initialize_from_env]
- Omit null/None values when writing json objects.

## 0.8.1 - 2023-07-14
- Logging updates in [planet_auth.OidcMultiIssuerValidator][] for better observability.

## 0.8.0 - 2023-06-13
- Add enforcement checks to OAuth access token validators for checking scope grants.

## 0.7.1 - 2023-06-10
- CI/CD change to automatically drop git tags when publishing a package to Pypi servers

## 0.7.0 - 2023-05-22
- Split the CLI off into a package that is separate from the auth library.

## 0.6.4 - 2023-05-13
- Add `X-Planet-App` header to outbound requests.  When acting as a auth server client,
  this will always be set.  When acting as a resource server client helper, this
  will only be set if it has not already been set.

## 0.6.3 - 2023-04-20
- Update frozen requirements for docker build
- Minor documentation fixes

## 0.6.2 - 2023-03-27
- `profile create` wizard basic functionality, and supporting changes to core library classes.

## 0.6.1 - 2023-03-24
### Changes
- Fixes to embedded `plauth` command
- Updates and fixes to examples.
- Debug log updates around file I/O.
- Profile command enhancements from another old working branch (incomplete)

## 0.6.0 - 2023-03-21
### Changes
- Changed the client config field `default_request_scopes` to `scopes` for OIDC auth client configs.
- Changed the client config field `default_request_audiences` to `audiences` for OIDC auth client configs.
- Clarifies the behavior of [planet_auth.OidcAuthClient][] with respect the handling of the expected audience
  handling and configuration for local access token validation.
- Changes to [planet_auth.OidcMultiIssuerValidator][] interface to better accommodate OAuth providers
  with different back-end models.  This also makes the configuration of auth clients used for validator
  use cases more intuitive.
