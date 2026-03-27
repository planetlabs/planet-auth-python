Run unit tests using nox. Pass any additional arguments through to pytest via nox's posargs.

Examples:
- Run the full unit test suite: `nox -s pytest`
- Run tests matching a keyword: `nox -s pytest -- -k "test_name"`
- Run a specific test file: `nox -s pytest -- tests/test_planet_auth/unit/path/to/test_file.py`

Run: `nox -s pytest -- $ARGUMENTS`

Note: When `-k` is used, nox automatically disables coverage (`--no-cov`).
Default test paths are configured in pyproject.toml and include `tests/test_planet_auth/unit` and `tests/test_planet_auth_utils/unit`.
