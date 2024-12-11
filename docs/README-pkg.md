# Planet Auth Utility Library

This library provides generic authentication utilities for clients obtain access
tokens, and for services validating access tokens.  The architecture of the code
is intended to be easily extensible to new authentication protocols in the future.
Currently, this library supports OAuth2, Planet's legacy proprietary authentication
protocols, and static API keys.

This library does not make any assumptions about the specific environment in which
it is operating, leaving that for higher level applications to configure.

The [Planet SDK for Python](https://developers.planet.com/docs/pythonclient/)
leverages this library, and is pre-configured for the Planet Cloud Service used
by customers.
