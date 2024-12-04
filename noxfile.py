import nox

nox.options.stop_on_first_error = True
nox.options.reuse_existing_virtualenvs = False

nox.options.sessions = ["test", "lint"]


@nox.session(python=["3.9", "3.10", "3.11", "3.12", "3.13"])
def test(session):
    session.install("-e", ".[test]")

    options = session.posargs
    if "-k" in options:
        options.append("--no-cov")
    # Default test set selection done in pyproject.toml
    session.run("pytest", "-v", *options)


@nox.session
def lint(session):
    session.install("-e", ".[test]")
    session.run("black", "--check", "--diff", "--color", ".")
    # This represents Devrel's copy-and-paste linting.
    # session.run("flake8", *source_files)
    # session.run('yapf', '--diff', '-r', *source_files)
