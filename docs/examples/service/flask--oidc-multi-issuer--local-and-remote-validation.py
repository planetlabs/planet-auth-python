import http
import logging

import planet_auth

import re
from flask import Flask, make_response, request
from functools import wraps


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
# In order to perform remote token validation with the auth server, we must
# be registered with the auth server as a client ourselves, even if we never
# intend to act as a client and obtain access tokens of our own.  In this
# example, we are registered as a confidential client (one with a client
# secret) that is permitted client credentials OAuth flow and grant type.
# This is not the only possibility.

# TODO: we should have an example of how to use a built-in provider to provide
#     named application server trust environments through use of the
#     planet_auth_utils.PlanetAuthFactory.initialize_resource_server_validator
validator_auth_client_config = {
    "client_type": "oidc_client_credentials_secret",
    "auth_server": "_trusted_auth_server_issuer_",
    "audiences": ["_expected_token_audience_"],
    "client_id": "_your_client_id_",
    "client_secret": "_your_client_secret_",
}

auth_validator = planet_auth.OidcMultiIssuerValidator.from_auth_server_configs(
    trusted_auth_server_configs=[validator_auth_client_config]
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
def flask_auth_worker(do_remote_check: bool):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise planet_auth.AuthException("Authorization header not provided")

    scheme, token = re.split(" +", auth_header.strip(), 1)
    if scheme != "Bearer":
        raise planet_auth.AuthException("Unrecognized authentication token scheme: {}".format(scheme))

    # throws auth failures
    return auth_validator.validate_access_token(token=token, do_remote_revocation_check=do_remote_check)


def flask_auth_decorator(do_remote_check: bool = False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kws):
            try:
                local_validation, remote_validation = flask_auth_worker(do_remote_check)
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
@app.route("/")
@flask_auth_decorator()
def hello():
    return "Hello World!"


@app.route("/secret")
@flask_auth_decorator(do_remote_check=True)
def secret():
    return "Sensitive info. Extra checks performed for revoked access tokens."


if __name__ == "__main__":
    app.run(host="localhost", port=5001)
