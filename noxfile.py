import os
import sys

import nox

nox.options.stop_on_first_error = True
nox.options.reuse_existing_virtualenvs = False

# Default sessions - all tests, but not packaging
nox.options.sessions = [
    "black_lint",
    "pytest",
    "semgrep_src",
    "mypy",
    "pyflakes_src",
    "pyflakes_examples",
    "pyflakes_tests",
    "pylint_src",
    "pylint_examples",
    "pylint_tests",
]

_DEFAULT_PYTHON = "3.13"
_ALL_PYTHON = ["3.9", "3.10", "3.11", "3.12", "3.13"]


@nox.session(python=_ALL_PYTHON)
def pytest(session):
    """Run Pytest test suites"""
    session.install("-e", ".[test]")

    options = session.posargs
    if "-k" in options:
        options.append("--no-cov")
    # Default test set selection done in pyproject.toml
    # session.run("pytest", "--log-cli-level=DEBUG", "-v", *options)
    session.run("pytest", "-v", *options)


@nox.session(python=_DEFAULT_PYTHON)
def semgrep_src(session):
    """Scan the code for security problems with semgrep"""
    session.install("-e", ".[test]")
    # session.run("semgrep", "scan", "--strict", "--verbose", "--error", "--junit-xml", "--junit-xml-output=semgrep-src.xml", "src")
    session.run("semgrep", "scan", "--strict", "--verbose", "--error", "src")


@nox.session(python=_DEFAULT_PYTHON)
def black_lint(session):
    """Check code formatting with Black"""
    session.install("-e", ".[test]")
    session.run("black", "--verbose", "--check", "--diff", "--color", ".")


@nox.session(python=_DEFAULT_PYTHON)
def black_format(session):
    """Fix code formatting with Black"""
    session.install("-e", ".[test]")
    session.run("black", "--verbose", ".")


@nox.session(python=_DEFAULT_PYTHON)
def mypy(session):
    """Lint all of the code with mypy"""
    session.install("-e", ".[test, examples]")
    session.run("mypy", "--install-type", "--non-interactive", "--junit-xml", "mypy.xml")


@nox.session(python=_DEFAULT_PYTHON)
def pyflakes_src(session):
    """Lint the library code with Pyflakes"""
    session.install("-e", ".[test]")
    session.run("pyflakes", "src")


@nox.session(python=_DEFAULT_PYTHON)
def pyflakes_examples(session):
    """Lint the example code with Pyflakes"""
    session.install("-e", ".[test, examples]")
    session.run("pyflakes", "docs/examples")


@nox.session(python=_DEFAULT_PYTHON)
def pyflakes_tests(session):
    """Lint the test code with Pyflakes"""
    session.install("-e", ".[test]")
    session.run("pyflakes", "tests")


@nox.session(python=_DEFAULT_PYTHON)
def pylint_src(session):
    """Lint the library code with Pylint"""
    session.install("-e", ".[test]")
    session.run("pylint", "src")


@nox.session(python=_DEFAULT_PYTHON)
def pylint_examples(session):
    """Lint the example code with Pylint"""
    session.install("-e", ".[test, examples]")
    session.run("pylint", "docs/examples")


@nox.session(python=_DEFAULT_PYTHON)
def pylint_tests(session):
    """Lint the test code with Pylint"""
    session.install("-e", ".[test]")
    session.run("pylint", "--disable", "protected-access", "--disable", "unused-variable", "tests")


@nox.session(python=_DEFAULT_PYTHON)
def pkg_build_wheel(session):
    """Build distribution package files"""
    session.install("-e", ".[build]")
    session.run("pyproject-build")
    # session.run("simple503", "-B", "dist", "dist")


@nox.session(python=_DEFAULT_PYTHON)
def pkg_build_local_dist(session):
    """Build distribution package files, and build a local simple PyPi directory that can be used by pip for local testing."""
    session.install("-e", ".[build]")
    session.run("pyproject-build")
    session.run("simple503", "-B", "dist", "dist")


@nox.session(python=_DEFAULT_PYTHON)
def pkg_check(session):
    """Check the built distribution files for errors"""
    session.install("-e", ".[build]")
    session.run("twine", "check", "--strict", "dist/*.whl", "dist/*.tar.gz")


def _publish_pypi(session, repo_url, token):
    session.install("-e", ".[build]")
    session.run(
        "twine",
        "upload",
        "--non-interactive",
        # "--verbose",
        "--username",
        "__token__",
        "--password",
        token,
        "--repository-url",
        repo_url,
        # "--repository",
        # repo_name,
        "dist/*.whl",
        "dist/*.tar.gz",
    )


@nox.session(python=_DEFAULT_PYTHON)
def pkg_publish_pypi_prod(session):
    """Publish packages to the production PyPi server"""
    token = os.getenv("NOX_PYPI_API_TOKEN")
    if not token:
        sys.exit("NOX_PYPI_API_TOKEN must be set in the environment with the PyPi access token")
    _publish_pypi(session, "https://upload.pypi.org/legacy", token)


@nox.session(python=_DEFAULT_PYTHON)
def pkg_publish_pypi_test(session):
    """Publish packages to the test PyPi server"""
    token = os.getenv("NOX_PYPI_API_TOKEN")
    if not token:
        sys.exit("NOX_PYPI_API_TOKEN must be set in the environment with the PyPi access token")
    _publish_pypi(session, "https://test.pypi.org/legacy/", token)


@nox.session(python=_DEFAULT_PYTHON)
def mkdocs_build(session):
    """Build the documentation locally"""
    session.install("-e", ".[docs]")
    session.run("mkdocs", "-v", "build", "--clean")


@nox.session(python=_DEFAULT_PYTHON)
def mkdocs_checklinks(session):
    """Check links in the documentation"""
    session.install("-e", ".[docs]")
    session.run("mkdocs-linkcheck", "-v", "-r", "docs")


@nox.session(python=_DEFAULT_PYTHON)
def mkdocs_serve(session):
    """Build the documentation and serve locally over HTTP. The server will watch for updates."""
    session.install("-e", ".[docs]")
    session.run("mkdocs", "-v", "serve")


@nox.session(python=_DEFAULT_PYTHON)
def mkdocs_publish_readthedocs(session):
    """(NOT IMPLEMENTED) Publish the documentation to ReadTheDocs.com"""
    session.install("-e", ".[build, docs]")
    # TODO - Manual doc publishing
    print(
        "ERROR: Read The Docs publishing not implemented in the noxfile."
        "  Documentation publishing is triggered via GitHub webhook."
    )
    assert False
