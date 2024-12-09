import nox

nox.options.stop_on_first_error = True
nox.options.reuse_existing_virtualenvs = False

nox.options.sessions = ["test", "lint"]

_DEFAULT_PYTHON = "3.13"
_ALL_PYTHON = ["3.9", "3.10", "3.11", "3.12", "3.13"]


@nox.session(python=_ALL_PYTHON)
def pytest(session):
    session.install("-e", ".[tests]")

    options = session.posargs
    if "-k" in options:
        options.append("--no-cov")
    # Default test set selection done in pyproject.toml
    session.run("pytest", "-v", *options)


@nox.session(python=_DEFAULT_PYTHON)
def semgrep_src(session):
    session.install("-e", ".[tests]")
    # session.run("semgrep", "scan", "--strict", "--verbose", "--error", "--junit-xml", "--junit-xml-output=semgrep-src.xml", "src")
    session.run("semgrep", "scan", "--strict", "--verbose", "--error", "src")


@nox.session(name="black-lint", python=_DEFAULT_PYTHON)
def black_lint(session):
    session.install("-e", ".[tests]")
    session.run("black", "--verbose", "--check", "--diff", "--color", ".")


@nox.session(python=_DEFAULT_PYTHON)
def black_format(session):
    session.install("-e", ".[tests]")
    session.run("black", "--verbose", ".")


@nox.session(python=_DEFAULT_PYTHON)
def mypy(session):
    session.install("-e", ".[tests, examples]")
    session.run("mypy", "--install-type", "--non-interactive", "--junit-xml", "mypy.xml")


@nox.session(python=_DEFAULT_PYTHON)
def pyflakes_src(session):
    session.install("-e", ".[tests]")
    session.run("pyflakes", "src")


@nox.session(python=_DEFAULT_PYTHON)
def pyflakes_examples(session):
    session.install("-e", ".[tests, examples]")
    session.run("pyflakes", "docs/examples")


@nox.session(python=_DEFAULT_PYTHON)
def pyflakes_tests(session):
    session.install("-e", ".[tests]")
    session.run("pyflakes", "tests")


@nox.session(python=_DEFAULT_PYTHON)
def pylint_src(session):
    session.install("-e", ".[tests]")
    session.run("pylint", "src")


@nox.session(python=_DEFAULT_PYTHON)
def pylint_examples(session):
    session.install("-e", ".[tests, examples]")
    session.run("pylint", "docs/examples")


@nox.session(python=_DEFAULT_PYTHON)
def pylint_tests(session):
    session.install("-e", ".[tests]")
    session.run("pylint", "--disable", "protected-access", "--disable", "unused-variable", "tests")


@nox.session(python=_DEFAULT_PYTHON)
def build_wheel(session):
    session.install("-e", ".[build]")
    session.run("pyproject-build")
    # session.run("simple503", "-B", "dist", "dist")


@nox.session(python=_DEFAULT_PYTHON)
def build_local_dist(session):
    session.install("-e", ".[build]")
    session.run("pyproject-build")
    session.run("simple503", "-B", "dist", "dist")


@nox.session(python=_DEFAULT_PYTHON)
def mkdocs_build(session):
    session.install("-e", ".[docs]")
    session.run("mkdocs", "-v", "build")


@nox.session(python=_DEFAULT_PYTHON)
def mkdocs_serve(session):
    session.install("-e", ".[docs]")
    session.run("mkdocs", "-v", "serve")


@nox.session(python=_DEFAULT_PYTHON)
def pyblish_pypi(session):
    session.install("-e", ".[build]")
    # TODO
    assert False


@nox.session(python=_DEFAULT_PYTHON)
def pyblish_readthedocs(session):
    session.install("-e", ".[build, docs]")
    # TODO
    assert False
