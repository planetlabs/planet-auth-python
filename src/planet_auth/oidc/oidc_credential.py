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

import time
from typing import Optional

from planet_auth.credential import Credential
from planet_auth.storage_utils import InvalidDataException, ObjectStorageProvider
from planet_auth.oidc.token_validator import TokenValidator, InvalidArgumentException


class FileBackedOidcCredential(Credential):
    """
    Credential object for storing OAuth/OIDC tokens.
    Credential should conform to the "token" response
    defined in RFC 6749 for OAuth access tokens with OIDC extensions
    for ID tokens.
    """

    def __init__(self, data=None, credential_file=None, storage_provider: Optional[ObjectStorageProvider] = None):
        super().__init__(data=data, file_path=credential_file, storage_provider=storage_provider)
        self._augment_rfc6749_data()

    def check_data(self, data):
        """
        Check that the supplied data represents a valid OAuth/OIDC token object.
        """
        super().check_data(data)
        if not data.get("access_token") and not data.get("id_token") and not data.get("refresh_token"):
            raise InvalidDataException(
                message="'access_token', 'id_token', or 'refresh_token' not found in file {}".format(self._file_path)
            )

    def _augment_rfc6749_data(self):
        # RFC 6749 includes an optional "expires_in" expressing the lifespan of
        # the token.  But without knowing when a token was issued it tells us
        # nothing about whether a token is actually valid.
        #
        # This function lest us augment our representation of this data to
        # make this credential useful when reconstructed from saved data
        # at a time that is distant from when the token was obtained from the
        # authorization server.
        #
        # Edge case - It's possible that a JWT ID token has an expiration time
        # that is different from the access token. It's also possible that
        # we have a refresh token and not any other tokens (this state could
        # be used for bootstrapping). We are really only tracking
        # access token expiration at this time.
        if not self._data:
            return

        try:
            access_token_str = self.access_token()
            if access_token_str:
                (_, jwt_hazmat_body, _) = TokenValidator.hazmat_unverified_decode(access_token_str)
            else:
                jwt_hazmat_body = None
        except InvalidArgumentException:
            # Proceed as if it's not a JWT.
            jwt_hazmat_body = None

        # It's possible for the combination of a transparent bearer token,
        # saved iat and exp values, and a expires_in value to be
        # over-constrained.  We apply the following priority, from highest
        # to lowest:
        #     - Bearer token claims
        #     - Saved values in the credential file
        #     - Newly calculated values
        # If a reasonable expiration time cannot be derived,
        # tokens are assumed to never expire.
        rfc6749_lifespan = self._data.get("expires_in", 0)
        if jwt_hazmat_body:
            _iat = jwt_hazmat_body.get("iat", self._data.get("_iat", int(time.time())))
            _exp = jwt_hazmat_body.get("exp", self._data.get("_exp", None))
        else:
            _iat = self._data.get("_iat", int(time.time()))
            _exp = self._data.get("_exp", None)

        if _exp is None and rfc6749_lifespan > 0:
            _exp = _iat + rfc6749_lifespan

        self._data["_iat"] = _iat
        self._data["_exp"] = _exp

    def set_data(self, data, copy_data: bool = True):
        """
        Set credential data for an OAuth/OIDC credential.  The data structure is expected
        to be an RFC 6749 /token response structure.
        """
        super().set_data(data, copy_data)
        self._augment_rfc6749_data()

    def access_token(self):
        """
        Get the current access token.
        """
        return self.lazy_get("access_token")

    def id_token(self):
        """
        Get the current ID token.
        """
        return self.lazy_get("id_token")

    def refresh_token(self):
        """
        Get the current refresh token.
        """
        return self.lazy_get("refresh_token")
