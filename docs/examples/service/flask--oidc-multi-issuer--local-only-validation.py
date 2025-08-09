import http
import logging
import os
import re
from flask import Flask, make_response, request
from functools import wraps
from typing import List, Optional

import planet_auth

#############################################################################
# Logging Configuration
#############################################################################
# In a simple environment, the global logging format will be
# applied. This example removes all formatting around the log message from
# the outer application, allowing the library's logging to be emitted with
# no further decoration.  The auth library will emit logs in a json
# format, so removing surrounding formatting insures that the json will be
# parsable:
logging.basicConfig(format="%(message)s", level=logging.DEBUG)

# Alternatively, we can tell the library to use python structured logging.
# The exact appearance of the logs in this case will be dependent on the
# configuration of the logger.  When structured loging is used, the library
# will log using the python logger's `extra` data.  In most cases,
# this would be expected to be done in conjunction with a call to
# setPyLoggerForAuthLogger() (see below).
#
#     planet_auth.setStructuredLogging()

# What logger will be used can also be controlled.  By default, the library
# will use a logger it creates internally that is global to the library.
# Applications may set the logger for the library to "None" to quite all,
# or may set it to any logger of their choice.:
#
#     planet_auth.setPyLoggerForAuthLogger(None)
#   or
#     planet_auth.setPyLoggerForAuthLogger(logging.getLogger(name="my-custom-auth-lib-logger"))


#############################################################################
# Validator Configuration
#############################################################################
# Never ever ever EVER NEVER EVER accept authorities that cross trust realms
# in the same service.  This is a recipe for compromising the integrity of
# your secure environments.
#
# NEVER. NEVER EVER.
# Do not cross the streams.
# Seriously.  Don't do it.

auth_validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
    trusted_auth_server_configs=[
        {
            "auth_server": os.getenv("MY_TRUSTED_ISSUER_PRIMARY"),
            "audiences": [os.getenv("MY_TRUSTED_AUDIENCE_PRIMARY")],
        },
        {
            "auth_server": os.getenv("MY_TRUSTED_ISSUER_DEPRECATED"),
            "audiences": [os.getenv("MY_TRUSTED_AUDIENCE_DEPRECATED")],
        },
    ],
)


#############################################################################
# Connecting validator to flask using decorators (your service needs may vary)
#############################################################################
# Note: This example only enforces basic authentication - that the user has
#       authenticated to a trusted auth server and presented a valid access
#       token.  In practice, services are also responsible for determining
#       whether that particular client user is allowed to make a particular
#       request.  Services may have their own database or configuration that
#       governs this. The overall service architecture may define token
#       claims that convey particular privileges. Neither of these are
#       demonstrated by this example.
@planet_auth.AuthException.recast(ValueError)
def flask_auth_worker(do_remote_check: bool, scopes_any_of=Optional[List[str]]):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise planet_auth.AuthException("Authorization header not provided")

    scheme, token = re.split(" +", auth_header.strip(), 1)
    if scheme != "Bearer":
        raise planet_auth.AuthException("Unrecognized authentication token scheme: {}".format(scheme))

    # this call will throw auth failures
    return auth_validator.validate_access_token(
        token=token, do_remote_revocation_check=do_remote_check, scopes_anyof=scopes_any_of
    )


def flask_auth_decorator(do_remote_check: bool = False, scopes_any_of=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kws):
            try:
                # This example does not pass the results of the
                # validation back to the flask app at this time.
                local_validation, remote_validation = flask_auth_worker(
                    do_remote_check=do_remote_check, scopes_any_of=scopes_any_of
                )
                # If you have additional application specific checks
                # you wish to make at the granularity of the decorator,
                # this is a reasonable place to do them. After having
                # passed the checks above, the contents of the token
                # as returned in local_validation / remote_validation
                # can be considered trusted.
            except planet_auth.AuthException as ae:
                # Don't leak information to unauthorized clients in the response.
                # It's fine to be more detailed in server side logs.
                logging.warning("Auth failure: {}".format(ae))
                # Return or abort, as per your application conventions.
                return make_response("UNAUTHORIZED", http.HTTPStatus.UNAUTHORIZED)
                # abort(http.HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED")
            return fn(*args, **kws)

        return wrapper

    return decorator


#############################################################################
# Main flask application
#############################################################################
app = Flask(__name__)


# Order of decorators matters
@app.route("/require-scopes")
@flask_auth_decorator(scopes_any_of=["required_scope1", "required_scope2"])
def require_scopes():
    return "Hello World! from a scope restricted endpoint.\n"


@app.route("/")
@flask_auth_decorator(scopes_any_of=None)
def hello():
    return "Hello World!\n"


if __name__ == "__main__":
    # Control how the library emits its logs:
    # planet_auth.setStringLogging()
    # planet_auth.setStructuredLogging()
    app.run(host="localhost", port=5001)
