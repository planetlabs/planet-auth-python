# Changelog

## 2.3.0 - 2025-10-20
- Improve the user experience around old stale sessions that appear to be
  initialized, but are actually expired.  This is done by providing the new
  utility method: `Auth.ensure_request_authenticator_is_ready()`.
- Save computed expiration time and issued time in token files. This allows
  for the persistence of this information when dealing with opaque tokens.
  - **Note**: Previously saved OAuth access tokens that are not JWTs with
    an `exp` claim that can be inspected will be considered to expire in
    `expires_in` seconds from the time they are loaded, since the time
    they were issued was not saved in the past.
- Support non-expiring tokens.

## 2.2.0 - 2025-10-02
- Update supported python versions.
  Support for 3.9 dropped.  Support through 3.14 added.

## 2.1.1 - 2025-08-11
- Add py.typed to all top level packages

## 2.1.0 - 2025-07-09
- Initial public release targeting integration with the
  [Planet Client for Python](https://github.com/planetlabs/planet-client-python).

## 2.0.11 - 2025-07-09
- Final 2.0 series development release.

## [Unreleased: 2.0.*]
- All releases in the 2.0.X series are development releases, even if not
  tagged as such. This work included some shakedowns of the release pipelines.
