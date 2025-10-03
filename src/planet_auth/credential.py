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

from planet_auth.storage_utils import FileBackedJsonObject


class Credential(FileBackedJsonObject):
    """
    A storage backed credential.
    A credential is expected to be a json dict.  Per the base class default
    storage provider implementation, clear-text .json files or .sops.json files
    with field level encryption are supported.  Custom storage providers may
    offer different functionality.

    Subclass Implementor Notes:
        The `Credential` class reserves the data fields `_iat` and `_exp` for
        internal use.  These are used to record the time the credential was
        issued and the time that it expires respectively, expressed as seconds
        since the epoch.  A None or NULL value for `_exp` indicates that
        the credential never expires.

        This base class does not set these values.  It is the responsibility
        of subclasses to set these values as appropriate.  If left unset,
        the credential will be treated as a non-expiring credential with an
        indeterminate issued time.

        Subclasses that wish to provide values should do so in their
        constructor and in their `set_data()` methods.
    """

    def __init__(self, data=None, file_path=None, storage_provider=None):
        super().__init__(data=data, file_path=file_path, storage_provider=storage_provider)

    def expiry_time(self) -> Optional[int]:
        """
        The time that the credential expires, expressed as seconds since the epoch.
        """
        return self.lazy_get("_exp")

    def issued_time(self) -> Optional[int]:
        """
        The time that the credential was issued, expressed as seconds since the epoch.
        """
        return self.lazy_get("_iat")

    def is_expiring(self) -> bool:
        """
        Return true if the credential has an expiry time.
        """
        return self.expiry_time() is not None

    def is_non_expiring(self) -> bool:
        """
        Return true if the credential never expires.
        """
        return not self.is_expiring()

    def is_expired(self, at_time: Optional[int] = None) -> bool:
        """
        Return true if the credential is expired at the specified time.
        If no time is specified, the current time is used.
        Non-expiring credentials will always return false.
        """
        if self.is_non_expiring():
            return False

        if at_time is None:
            at_time = int(time.time())

        exp = self.expiry_time()
        return at_time >= exp  # type: ignore[operator]

    def is_not_expired(self, at_time: Optional[int] = None) -> bool:
        """
        Return true if the credential is not expired at the specified time.
        If no time is specified, the current time is used.
        Non-expiring credentials will always return true.
        """
        return not self.is_expired(at_time)
