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


class FileBackedPlanetLegacyApiKey(Credential):
    """
    Credential object for storing Planet Legacy API Keys
    """

    def __init__(
        self, api_key=None, jwt=None, api_key_file=None, storage_provider: Optional[ObjectStorageProvider] = None
    ):
        if api_key or jwt:
            # "key" was used by the old Python SDK.
            # Keeping this json key name and file format so this class
            # should just work with tokens saved by pre-OAuth versions of the SDK.
            init_data = {"key": api_key, "jwt": jwt}
        else:
            init_data = None
        super().__init__(data=init_data, file_path=api_key_file, storage_provider=storage_provider)

    def check_data(self, data):
        """
        Check that the supplied data represents a valid Planet Legacy API Key object.
        """
        super().check_data(data)
        if not data.get("key"):
            raise InvalidDataException(message="'key' not found in file " + str(self._file_path))

    def legacy_api_key(self):
        """
        Get the current API key.
        """
        return self.lazy_get("key")

    # Duck type compatibility with FileBackedApiKey (Static API key)
    def api_key(self):
        return self.legacy_api_key()

    def legacy_jwt(self):
        """
        Get the saved legacy JWT.
        """
        return self.lazy_get("jwt")
