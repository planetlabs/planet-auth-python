# Copyright 2024 Planet Labs PBC.
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

from planet_auth.planet_legacy.legacy_api_key import FileBackedPlanetLegacyApiKey
from planet_auth.request_authenticator import CredentialRequestAuthenticator


class PlanetLegacyRequestAuthenticator(CredentialRequestAuthenticator):
    """
    Authenticate a request using a legacy Planet API key.  Currently,
    the credential file is now also capable of saving a JWT, but
    this authenticator makes no use of it.
    """

    TOKEN_PREFIX = "api-key"

    def __init__(self, planet_legacy_credential: FileBackedPlanetLegacyApiKey, **kwargs):
        super().__init__(credential=planet_legacy_credential, token_prefix=self.TOKEN_PREFIX, **kwargs)
        self._api_key_file = planet_legacy_credential

    def pre_request_hook(self):
        self._token_body = self._api_key_file.legacy_api_key()