# Planet Auth Utility Library <br/> {{ config.extra.site_version }}

## Overview
The Planet Auth Library provides generic authentication utilities for clients
and services.  For clients, it provides the means to obtain access tokens that
can be used to access network services.  For services, it provides tools to
validate the same access tokens.

The architecture of the code was driven by OAuth2, but is intended to be easily
extensible to new authentication protocols in the future.  Since clients
and resource servers are both themselves clients to authorization servers in
an OAuth2 deployment, this combining of client and server concerns in a single
library was seen as natural.

Currently, this library supports OAuth2, Planet's legacy proprietary
authentication protocols, and static API keys.

This library does not make any assumptions about the specific environment in which
it is operating, leaving that for higher level applications to configure.

The [Planet SDK for Python](https://developers.planet.com/docs/pythonclient/)
leverages this library, and is pre-configured for the Planet Insights Platform used
by customers.

## Installation
Install from PyPI using pip:

```bash
pip install planet-auth
```
