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

from planet_auth.storage_utils import FileBackedJsonObject


class Credential(FileBackedJsonObject):
    """
    A storage backed credential.
    A credential is expected to be a json dict.  Per the base class default
    storage provider implementation, clear-text .json files or .sops.json files
    with field level encryption are supported.  Custom storage providers may
    offer different functionality.
    """

    def __init__(self, data=None, file_path=None, storage_provider=None):
        super().__init__(data=data, file_path=file_path, storage_provider=storage_provider)
