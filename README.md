# Planet Auth Utility Library

The Planet Auth Library provides generic authentication utilities for clients
and for services.  For clients, it provides means to obtain access tokens that
can be used to access network services.  For services, it provides tools to
validate the same access tokens.

The [Planet SDK for Python](https://developers.planet.com/docs/pythonclient/)
leverages this library, and is pre-configured for the Planet Cloud Service used
by customers.

## Installation and Quick Start

The Planet Auth Library for Python is [hosted on PyPI](https://pypi.org/project/planet-auth/)
and can be installed via:

```console
pip install planet-auth
```

To install from source, first clone this repository, then navigate to the
root directory (where [`pyproject.toml`](./pyproject.toml) lives) and run:

```console
pip install .
```

## Using the Planet Auth Library
See the developer documentation at [Planet Auth on Read The Docs](TBD).

## Development
See [DEVELOPMENT](./DEVELOPMENT.md) for details on library development.

## Releasing

The release process is outlined in [RELEASE](RELEASE.md).
