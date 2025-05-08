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


class FileBackedApiKey(Credential):
    """
    Credential object for storing simple API key bearer tokens.
    """

    def __init__(
        self,
        api_key=None,
        prefix="Bearer",
        api_key_file=None,
        storage_provider: Optional[ObjectStorageProvider] = None,
    ):
        if api_key:
            init_data = {"api_key": api_key, "bearer_token_prefix": prefix}
        else:
            init_data = None

        super().__init__(data=init_data, file_path=api_key_file, storage_provider=storage_provider)

    def check_data(self, data):
        """
        Check that the supplied data represents a valid API key object.
        """
        super().check_data(data)
        if not data.get("api_key"):
            raise InvalidDataException(message="'api_key' not found in file " + str(self._file_path))
        if not data.get("bearer_token_prefix"):
            raise InvalidDataException(messae="'bearer_token_prefix' not found in file " + str(self._file_path))

    def api_key(self):
        """
        Get the current API Key.
        """
        return self.lazy_get("api_key")

    def bearer_token_prefix(self):
        """
        Get the bearer token prefix that is to be used with the API key.
        """
        return self.lazy_get("bearer_token_prefix")
