# Development

## Development Tools
All packages needed for different facets of development are specified as
"extra" packages.  Each of these may be installed using `pip`.  For example,
the following would install the extra packages needed for the operation of
the code samples in the documentation:

```console
pip install planet-auth[examples]
```

The following extra packages have been defined:
* `build` - Packages needed to build distribution packages.
* `docs` - Packages needed to build the documentation.
* `test` - Packages needed to run all the test and linting suites.
* `examples` - Packages needed by example code.
* `dev` - Meta package that combines `build`, `docs`, and `test`.

## Nox
[Nox](https://nox.thea.codes/) is the preferred mechanism for performing all
common development activities.  This includes running unit tests, linting,
code formatting, and static analysis.

For a complete list of supported activities, list nox sessions.:
```console
nox -l
```
