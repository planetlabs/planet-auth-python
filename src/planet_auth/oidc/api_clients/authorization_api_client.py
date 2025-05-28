# Copyright 2024-2025 Planet Labs PBC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import getpass
import http.server

import importlib.resources  # nosemgrep

from http import HTTPStatus
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Optional
from webbrowser import open_new

import planet_auth.logging.auth_logger
import planet_auth.oidc.util as oidc_util
from planet_auth.oidc import resources
from planet_auth.oidc.api_clients.api_client import OidcApiClientException

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()
DEFAULT_REDIRECT_LISTEN_PORT = 80
AUTH_TIMEOUT = 60


class AuthorizationApiException(OidcApiClientException):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class _OidcSigninCallbackHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP Server callbacks to handle OAuth redirects.
    This handler expects to be invoked as a callback after user
    authentication. When called after successful login, the request will
    contain an auth code that can be used to obtain tokens. Parsing of the
    results is not handled here. It is the caller's responsibility.  All the
    callback does is pass the request along.
    """

    def __init__(self, request, address, server, do_logging: bool = False, response_body: str = None):
        self._do_logging = do_logging
        self._response_body_str = response_body
        super().__init__(request, address, server)

    def do_GET(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.server.callback_raw_request_path = self.path
        self.wfile.write(bytes(self._response_body_str, "utf-8"))

    def log_message(self, *args, **kwargs) -> None:
        # do nothing to disable logging.  We let the caller control this so
        # they can hush the HTTP server logging regardless of the global log
        # level.
        if self._do_logging:
            return super().log_message(*args, **kwargs)


def _parse_authcode_from_callback(raw_request_path, expected_state):
    if not raw_request_path:
        raise AuthorizationApiException(message="Authorization callback was empty")

    auth_logger.debug(msg="Parsing callback request from authorization server" + raw_request_path)

    parsed_query_string = parse_qs(urlparse(raw_request_path).query)

    error_code = parsed_query_string.get("error")
    if error_code:
        # TODO: Can we unify this error parsing with that in the
        #       oidc api_client baseclass?
        error_description = parsed_query_string.get("error_description") or ["no error description"]
        raise AuthorizationApiException(
            message="Authorization error: {}: {}".format(error_code[0], error_description[0]),
            raw_response=raw_request_path,
        )

    state_array = parsed_query_string.get("state")
    state = None

    if state_array:
        state = state_array[0]
    if state != expected_state:
        raise AuthorizationApiException(
            message="Callback state did not match expected value. Expected: {}, Received: {}".format(
                expected_state, state
            ),
            raw_response=raw_request_path,
        )

    auth_code_array = parsed_query_string.get("code")
    auth_code = None
    if auth_code_array:
        auth_code = auth_code_array[0]
    if not auth_code:
        raise AuthorizationApiException(
            message="Failed to understand authorization callback. Callback request"
            " did not include an authorization code or a recognized error."
            " Raw callback request: " + raw_request_path,
            raw_response=raw_request_path,
        )

    return auth_code


class AuthorizationApiClient:
    """
    Low level API client for the OAuth Authorization endpoint. See
    RFC 6749 - The OAuth 2.0 Authorization Framework for protocol details.

    This is not a child of the OidcApiClient base class since, unlike
    most low level API clients, this class does not directly call the API.
    Rather, a web browser or other methods are used to interact with
    the API in most cases so that IDP redirects, MFA, and user
    interactive authentication can be performed.
    """

    def __init__(
        self, authorization_uri: str, authorization_callback_acknowledgement_response_body: Optional[str] = None
    ):
        """
        Create a new Authorization API Client.
        """
        self._authorization_uri = authorization_uri
        if authorization_callback_acknowledgement_response_body:
            self._authorization_callback_acknowledgement_response_body = (
                authorization_callback_acknowledgement_response_body
            )
        else:
            self._authorization_callback_acknowledgement_response_body = (
                importlib.resources.files(resources).joinpath("callback_acknowledgement.html").read_text("utf-8")
            )

    @staticmethod
    def prep_pkce_auth_payload(
        client_id: str,
        redirect_uri: str,
        requested_scopes: List[str],
        requested_audiences: List[str],
        pkce_code_challenge: str,
        extra: Dict,
    ) -> Dict:
        """
        Prepare the payload needed to make an authorization request to an
        OAuth authorization endpoint. This will usually be used to construct
        query parameters that are appended to the URL of the authorization
        endpoint, but some implementations are known to accept a POST rather
        than a GET with URL parameters.

        It should also be noted that this method does not prepare any sort
        of client authentication.  Depending on whether this is used in
        support of a confidential or non-confidential OAuth client, additional
        work may be required. The details of what may be required may
        vary depending on the auth server's demands of a confidential
        client; The auth server may require HTTP auth headers, or that
        additional assertions are added to the payload, or may require
        nothing at all.  This all depends on the auth server's configuration
        for the particular client.

        Parameters:
            client_id: The ID of the OAuth client requesting authorization.
            redirect_uri: The callback URI that should be used to return control
                to the client program after user authentication and authorization
                has been completed.
            requested_scopes: A list of strings specifying the scopes to
                request.
            requested_audiences: A list of strings specifying the audiences
                to request.
            pkce_code_challenge: PKCE challenge code.  The caller should generate
                this code along with a validation code that can be used to verify
                responses.
            extra: Dict of extra parameters to pass to the authorization endpoint.

        Returns:
            Returns a dict that is suitable for use in making an authorization request.

        Example:
            ```
            auth_url = AUTHORIZATION_ENDPOINT_URL + "?" + urlencode(prep_pkce_auth_payload(...))
            ```
        """
        if extra is None:
            extra = {}
        # "None" is pythonic, and does not mean anything to OAuth APIs.
        _extra = {k: v for k, v in extra.items() if v is not None}

        data = {
            **_extra,  # we do this first, because we want it to lose the race with explicit parameters. It is not intended for clobbering.
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": oidc_util.generate_nonce(8),
            "nonce": oidc_util.generate_nonce(32),
            "code_challenge": pkce_code_challenge,
            "code_challenge_method": "S256",
        }
        if requested_scopes:
            # Standard
            data["scope"] = " ".join(requested_scopes)
        if requested_audiences:
            # Used by Auth0. Others?
            data["audience"] = " ".join(requested_audiences)

        return data

    def authcode_from_pkce_auth_request_with_browser_and_callback_listener(
        self,
        client_id: str,
        redirect_uri: str,
        requested_scopes: List[str],
        requested_audiences: List[str],
        pkce_code_challenge: str,
        extra: Dict,
    ) -> str:
        """
        Request an authorization code by launching a web browser directed to the
        OAuth Authorization endpoint.  An HTTP listener will be set up to capture
        the browser redirect after interaction with the auth server and IDP is complete.

        Parameters:
            client_id: The ID of the OAuth client requesting authorization.
            redirect_uri: The callback URI that should be used to return control
                to the client program after user authentication and authorization
                has been completed.
            requested_scopes: A list of strings specifying the scopes to
                request.
            requested_audiences: A list of strings specifying the audiences
                to request.
            pkce_code_challenge: PKCE challenge code.  The caller should generate
                this code along with a validation code that can be used to verify
                responses.
            extra: Dict of extra parameters to pass to the authorization endpoint.

        Returns:
            Returns an auth code upon success. An exception should be raised upon error.
        """
        data = self.prep_pkce_auth_payload(
            client_id=client_id,
            redirect_uri=redirect_uri,
            requested_scopes=requested_scopes,
            requested_audiences=requested_audiences,
            pkce_code_challenge=pkce_code_challenge,
            extra=extra,
        )
        auth_request_uri = self._authorization_uri + "?" + urlencode(data)

        # HTTP server to catch the callback redirect from the browser
        # auth process
        auth_logger.debug(msg='Setting up listener for auth callback handler with URI "{}"'.format(redirect_uri))
        parsed_redirect_url = urlparse(redirect_uri)
        listen_port = parsed_redirect_url.port if parsed_redirect_url.port else DEFAULT_REDIRECT_LISTEN_PORT
        if (
            parsed_redirect_url.hostname
            and parsed_redirect_url.hostname.lower() != "localhost"
            and parsed_redirect_url.hostname != "127.0.0.1"
        ):
            raise AuthorizationApiException(
                message="Unexpected hostname in auth redirect URI. Expected"
                ' localhost URI, but received "{}"'.format(redirect_uri)
            )

        # Only bind to loopback! See
        # https://datatracker.ietf.org/doc/html/rfc8252#section-8.3
        http_server = http.server.HTTPServer(
            ("localhost", listen_port),
            lambda request, address, server: _OidcSigninCallbackHandler(
                request,
                address,
                server,
                do_logging=False,  # (logger.root.level <= logging.DEBUG),
                response_body=self._authorization_callback_acknowledgement_response_body,
            ),
        )
        http_server.timeout = AUTH_TIMEOUT

        # Don't kick off the browser until we are satisfied that the callback
        # handler is up and listening. UX team wanted this on the console
        print(
            "Opening browser for authorization and listening locally for"
            ' callback.\nIf this fails, retry with "no browser"'
            " option enabled.\n"
        )
        auth_logger.debug(msg='Opening browser with authorization URL : "{}"\n'.format(auth_request_uri))
        open_new(auth_request_uri)

        # Do we ever need to loop for multiple callbacks?
        # (No, this should never be needed.)
        http_server.handle_request()

        if hasattr(http_server, "callback_raw_request_path"):
            return _parse_authcode_from_callback(http_server.callback_raw_request_path, data["state"])
        else:
            raise AuthorizationApiException(
                message="Unknown error obtaining login tokens. No callback data was received."
            )

    def authcode_from_pkce_auth_request_with_tty_input(
        self,
        client_id: str,
        redirect_uri: str,
        requested_scopes: List[str],
        requested_audiences: List[str],
        pkce_code_challenge: str,
        extra: Dict,
    ) -> str:
        """
        Request an authorization code by prompting the user to visit a
        specific authorization URI, and then prompt the user for the
        resulting authorization code via a TTY prompt.  The redirect URI
        should point to an application that is capable of accepting the
        final callback from the authorization URI, and is ready to parse
        the response and provide the client with the authorization code
        so that it may be entered at the prompt.

        Parameters:
            client_id: The ID of the OAuth client requesting authorization.
            redirect_uri: The callback URI that should be used to return control
                to the client program after user authentication and authorization
                has been completed.
            requested_scopes: A list of strings specifying the scopes to
                request.
            requested_audiences: A list of strings specifying the audiences
                to request.
            pkce_code_challenge: PKCE challenge code.  The caller should generate
                this code along with a validation code that can be used to verify
                responses.
            extra: Dict of extra parameters to pass to the authorization endpoint.

        Returns:
            Returns an auth code upon success. An exception should be raised upon error.
        """
        # 1) Display URL for user to paste into browser.
        # 2) Wait for them to copy-paste the auth code URL.
        # X) The process of catching the redirect from the auth and parsing
        #    out the auth code is out of band of this code.
        data = self.prep_pkce_auth_payload(
            client_id=client_id,
            redirect_uri=redirect_uri,
            requested_scopes=requested_scopes,
            requested_audiences=requested_audiences,
            pkce_code_challenge=pkce_code_challenge,
            extra=extra,
        )
        auth_request_uri = self._authorization_uri + "?" + urlencode(data)
        print(
            "Please go to the following URL to proceed with login.\n"
            "After successful login, please provide the resulting"
            " authentication code.\n"
            "\n\t{}\n\n".format(auth_request_uri)
        )
        return getpass.getpass(prompt="Authentication code: ")
