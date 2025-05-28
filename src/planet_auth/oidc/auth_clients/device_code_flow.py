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

import pyqrcode  # type: ignore
import time
from abc import ABC
from typing import List, Optional
from webbrowser import open_new

import planet_auth.logging.auth_logger

from planet_auth.auth_client import AuthClientException
from planet_auth.oidc.auth_client import (
    OidcAuthClientConfig,
    OidcAuthClient,
    OidcAuthClientWithNoneClientAuth,
)
from planet_auth.oidc.auth_client_with_client_pubkey import (
    OidcAuthClientWithClientPubkey,
    OidcAuthClientWithPubKeyClientConfig,
)
from planet_auth.oidc.auth_client_with_client_secret import (
    OidcAuthClientWithClientSecretClientConfig,
    OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment,
)
from planet_auth.oidc.oidc_credential import FileBackedOidcCredential
from planet_auth.oidc.auth_client_default_authenticators import (
    OidcAuthClientWithRefreshingOidcTokenRequestAuthenticator,
)


auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


class DeviceCodeAuthClientException(AuthClientException):
    pass


class DeviceCodeClientConfig(OidcAuthClientConfig):
    """
    Configuration required for [planet_auth.DeviceCodeAuthClient][]
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_device_code",
            "auth_client_class": DeviceCodeAuthClient,
            "display_name": "Device Code",
            "description": "OAuth2 Device Code Flow for a non-confidential client.",
            "config_hints": super().meta().get("config_hints"),
        }


class DeviceCodeAuthClientBase(OidcAuthClientWithRefreshingOidcTokenRequestAuthenticator, OidcAuthClient, ABC):
    def __init__(self, client_config: DeviceCodeClientConfig):
        super().__init__(client_config)
        self._devicecode_client_config = client_config

    def device_login_initiate(
        self,
        requested_scopes: List[str] = None,
        requested_audiences: List[str] = None,
        extra: Optional[dict] = None,
        **kwargs,
    ) -> dict:
        """
        Obtain tokens from the OIDC auth server using the Device Code OAuth
        flow.  This method initiates the device login process with the auth
        service.  A dictionary that complies to [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)
        will be return upon success that can be used by the client application
        to prompt the user.  After prompting the user, `device_login_complete()`
        should be called to complete the login process.

        Parameters:
            requested_scopes: a list of strings specifying the scopes to
                request.
            requested_audiences: a list of strings specifying the audiences
                to request.
            extra: a dict extra data to pass to the authorization server.
         Returns:
            A RFC 8628 compliant dictionary that can be used by the called
            to prompt the user to complete device authentication.
            This dictionary should be passed to `device_login_complete()`
            to finish the login process.
        """
        final_requested_scopes, final_requested_audiences, final_extra = self._apply_config_fallback(
            requested_scopes=requested_scopes, requested_audiences=requested_audiences, extra=extra
        )

        return self.device_authorization_client().request_device_code(
            client_id=self._oidc_client_config.client_id(),
            requested_scopes=final_requested_scopes,
            requested_audiences=final_requested_audiences,
            auth_enricher=self._client_auth_enricher,
            extra=final_extra,
        )

    def device_login_complete(self, initiated_login_data: dict) -> FileBackedOidcCredential:
        """
        Obtain tokens from the OIDC auth server using the Device Code OAuth
        flow. This method completes the process initiated by a call to `device_login_initiate()`.

        Parameters:
            initiated_login_data: The dictionary returned from a successful call to
                `device_login_initiate()`
         Returns:
            A FileBackedOidcCredential object
        """
        # Wait one poll interval before querying.
        poll_interval = initiated_login_data.get("interval", 5)  # Default specified in RFC 8628
        time.sleep(poll_interval)
        token_json = self.token_client().poll_for_token_from_device_code(
            client_id=self._oidc_client_config.client_id(),
            device_code=initiated_login_data.get("device_code"),
            timeout=initiated_login_data.get("expires_in"),
            poll_interval=poll_interval,
            auth_enricher=self._client_auth_enricher,
        )
        return FileBackedOidcCredential(token_json)

    def _oidc_flow_login(
        self,
        allow_open_browser: Optional[bool],
        allow_tty_prompt: Optional[bool],
        requested_scopes: Optional[List[str]],
        requested_audiences: Optional[List[str]],
        extra: Optional[dict],
        display_qr_code: bool = False,
        **kwargs,
    ) -> FileBackedOidcCredential:
        """
        Obtain tokens from the OIDC auth server using the Device Code OAuth
        flow.

        Parameters:
            requested_scopes: a list of strings specifying the scopes to
                request.
            requested_audiences: a list of strings specifying the audiences
                to request.
            extra: a dict extra data to pass to the authorization server.
            allow_open_browser: specify whether login is permitted to open
                a browser window.
            allow_tty_prompt: specify whether login is permitted to request
                input from the terminal.
            display_qr_code: specify whether a QR code should be displayed on the tty
         Returns:
            A FileBackedOidcCredential object
        """
        self._warn_password_kwarg(**kwargs)
        self._warn_ignored_kwargs(["username", "password", "client_id", "client_secret"], **kwargs)

        if not allow_tty_prompt:
            # Without a TTY to confirm the authorization code with the user,
            # the client using this library really must use device_login_initiate and
            # device_login_complete and manage the user experience.
            raise DeviceCodeAuthClientException(message="Terminal input is required for device code login.")

        device_auth_response = self.device_login_initiate(
            requested_scopes=requested_scopes,
            requested_audiences=requested_audiences,
            extra=extra,
        )
        # "verification_uri_complete" is optional under the RFC.
        # "verification_uri" and "user_code" are not.
        verification_uri_complete = device_auth_response.get("verification_uri_complete")
        verification_uri = device_auth_response.get("verification_uri")
        user_code = device_auth_response.get("user_code")

        if allow_open_browser:
            if verification_uri_complete:
                print(f"Opening browser to login.\n" f"Confirm the authorization code when prompted: {user_code}\n")
                auth_logger.debug(msg=f'Opening browser with authorization URL: "{verification_uri_complete}"\n')
                open_new(verification_uri_complete)
            else:
                print(
                    f"Opening browser to login site {verification_uri}\n"
                    f"Enter authorization code when prompted: {user_code}\n"
                )
                auth_logger.debug(msg=f'Opening browser with authorization URL : "{verification_uri}"\n')
                open_new(verification_uri)  # type: ignore
        else:
            print("Please activate your client.")
            if verification_uri_complete:
                print(
                    f"Visit the activation site:\n"
                    f"\n\t{verification_uri_complete}\n"
                    f"\nand confirm the authorization code:\n"
                    f"\n\t{user_code}\n"
                )
                qr_uri = verification_uri_complete
            else:
                print(
                    f"Visit the activation site:\n"
                    f"\n\t{verification_uri}\n"
                    f"\nand enter the authorization code:\n"
                    f"\n\t{user_code}\n"
                )
                qr_uri = verification_uri

            if display_qr_code:
                qr_code = pyqrcode.create(content=qr_uri, error="L")
                print(f"Or, scan the QR code to complete login:\n\n{qr_code.terminal()}\n")

        return self.device_login_complete(device_auth_response)

    def can_login_unattended(self) -> bool:
        # Always requires user interaction
        return False


class DeviceCodeAuthClient(DeviceCodeAuthClientBase, OidcAuthClientWithNoneClientAuth):
    """
    AuthClient implementation that implements the OAuth device code grant
    to obtain user tokens.  This implementation is for public clients that cannot
    maintain client confidentiality.
    """

    # The base and mix-ins pretty much do it all.


class DeviceCodeWithClientSecretClientConfig(DeviceCodeClientConfig, OidcAuthClientWithClientSecretClientConfig):
    """
    Configuration required for [planet_auth.DeviceCodeWithClientSecretAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_device_code_secret",
            "auth_client_class": DeviceCodeWithClientSecretAuthClient,
            "display_name": "Device Code (Client Secret)",
            "description": "OAuth2 Devivce Code Flow for a confidential client using a shared client secret for authentication.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class DeviceCodeWithClientSecretAuthClient(
    DeviceCodeAuthClientBase, OidcAuthClientWithClientSecret_HttpBasicAuthEnrichment
):
    """
    AuthClient implementation that implements the OAuth device code grant
    to obtain user tokens.  This implementation is for confidential
    clients that use a client secret to protect the client confidentiality.
    """

    # The base and mix-ins pretty much do it all.
    def __init__(self, client_config: DeviceCodeWithClientSecretClientConfig):
        super().__init__(client_config)


class DeviceCodeWithPubKeyClientConfig(DeviceCodeClientConfig, OidcAuthClientWithPubKeyClientConfig):
    """
    Configuration required for [planet_auth.DeviceCodeWithPubKeyAuthClient][]
    """

    @classmethod
    def meta(cls):
        return {
            "client_type": "oidc_device_code_pubkey",
            "auth_client_class": DeviceCodeWithPubKeyAuthClient,
            "display_name": "Device Code (Public Key)",
            "description": "OAuth2 Device Code Flow for a confidential client using public key authentication.",
            "config_hints": super().meta().get("config_hints"),  # The superclasses have all we need.
        }


class DeviceCodeWithPubKeyAuthClient(DeviceCodeAuthClientBase, OidcAuthClientWithClientPubkey):
    """
    AuthClient implementation that implements the OAuth device code grant
    to obtain user tokens.  This implementation is for confidential
    clients that use a public/private keypair to protect the client confidentiality.
    """

    # The base and mix-ins pretty much do it all.
    def __init__(self, client_config: DeviceCodeWithPubKeyClientConfig):
        super().__init__(client_config)
