# Changelog

## 2.4.0 - TBD
- Incomplete auth client configurations may now be loaded, copied, and saved.
  Validation is split between checks that data is well-formed, which are
  applied on load and save, and checks that a configuration is complete,
  which are applied when an auth client is constructed.
  - New `AuthClientConfig` methods `required_config_keys()`,
    `missing_required_fields()`, and `is_complete()`.
  - New `FileBackedJsonObject.check_complete()` hook, applied by `check()`
    but not by load, set, or save.  `AuthClientConfig` implements it.
  - New exception `AuthClientConfigIncompleteException`, which reports the
    missing settings.
- `PlanetAuthFactory.initialize_auth_client_context()` resolves the profile,
  client ID, client secret, and API key settings independently, and combines
  them.  Incomplete template profiles, such as built-in M2M profiles that lack client
  credentials, may be combined with a client ID and secret from command line
  options, environment variables, or the user config file.  The resulting
  runtime profile is named `<profile>-<client id>`, and will never shadow
  a built-in profile.
  - New exception `ProfileConflictException`, raised when a combined
    profile would shadow a built-in profile.
  - Errors for incomplete profiles describe how to fix the problem.
- CLI improvements:
  - `profile copy` accepts incomplete source profiles, and new options
    `--auth-client-id`, `--auth-client-secret`, `--set KEY=VALUE`, and
    `--prompt/--no-prompt` to fill in missing settings.  It refuses to
    overwrite built-in profiles, or existing profiles without `--force`.
  - New `profile check` command.
  - `profile list` and `profile set` note incomplete profiles.
  - Commands that manage profiles remain usable when the selected profile
    is incomplete.
- **Behavior changes**:
  - When settings come from environment variables or the user config file,
    the profile, client credentials, and API key are now resolved with the
    same priority used for command line options.  Previously, a profile
    selected by `~/.planet.json` took priority over client credentials or an
    API key set in environment variables when the library was used directly,
    while CLI programs that map environment variables to options (such as
    the Planet SDK CLI) gave the environment variables priority.  Library and
    CLI use now agree: higher priority sources (environment variables) win
    over lower priority sources (config files), unless the settings can be
    combined.
  - Runtime profile names derived from client IDs are now normalized to be
    lowercase and file system safe.  Tokens previously saved for client IDs
    containing other characters will not be found, and a new token will
    be obtained.
  - `profile copy` no longer silently overwrites an existing profile.
    Use `--force` to overwrite.  It also refuses to create profiles with
    built-in profile names, and prompts for missing settings when attached
    to a terminal (use `--no-prompt` to disable).
  - `AuthClientConfig` objects may be constructed, loaded, and saved with
    incomplete configuration.  Errors for missing required settings are
    raised when an `AuthClient` is constructed, as
    `AuthClientConfigIncompleteException` (a subclass of
    `AuthClientConfigException`).  Error message text has changed.

## 2.3.2 - 2026-07-08
- Increase default timeout for auth code flow callback listener.
- Test updates and formatting related to upstream project changes.

## 2.3.1 - 2025-12-10
- Fix a bug where sops protected files would be rewritten without preserving
  their sops protection.

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
