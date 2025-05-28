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

from planet_auth.request_authenticator import CredentialRequestAuthenticator
from planet_auth.static_api_key.static_api_key import FileBackedApiKey


class FileBackedApiKeyRequestAuthenticator(CredentialRequestAuthenticator):
    """
    Load a bearer token from a file just in time for the request.
    Perform local checks on the validity of the token and throw
    if we think it will fail.
    """

    def __init__(self, api_key_credential: FileBackedApiKey, **kwargs):
        super().__init__(credential=api_key_credential, **kwargs)

    def pre_request_hook(self):
        self._credential.lazy_reload()
        self._token_body = self._credential.api_key()
        self._token_prefix = self._credential.bearer_token_prefix()
