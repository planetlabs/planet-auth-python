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

from typing import Optional

from planet_auth.credential import Credential
from planet_auth.storage_utils import InvalidDataException, ObjectStorageProvider


class FileBackedOidcCredential(Credential):
    """
    Credential object for storing OAuth/OIDC tokens.
    """

    def __init__(self, data=None, credential_file=None, storage_provider: Optional[ObjectStorageProvider] = None):
        super().__init__(data=data, file_path=credential_file, storage_provider=storage_provider)

    def check_data(self, data):
        """
        Check that the supplied data represents a valid OAuth/OIDC token object.
        """
        super().check_data(data)
        if not data.get("access_token") and not data.get("id_token") and not data.get("refresh_token"):
            raise InvalidDataException(
                message="'access_token', 'id_token', or 'refresh_token' not found in file {}".format(self._file_path)
            )

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
