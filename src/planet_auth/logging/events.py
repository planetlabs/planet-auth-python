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

from enum import auto
from strenum import StrEnum


class AuthEvent(StrEnum):
    """
    Auth Events.

    Events exist to provide structure to log messages, with the
    initial use case in mind being building dashboards from log messages.
    Many events are error conditions, and these will overlap with
    exceptions, but not events indicate errors.
    """

    TRACE = auto()
    TOKEN_VALID = auto()
    TOKEN_INVALID = auto()
    TOKEN_INVALID_BAD_ALGORITHM = auto()
    TOKEN_INVALID_BAD_ISSUER = auto()
    TOKEN_INVALID_BAD_NONCE = auto()
    TOKEN_INVALID_BAD_SCOPE = auto()
    TOKEN_INVALID_BAD_SIGNING_KEY = auto()
    TOKEN_INVALID_EXPIRED = auto()
    TOKEN_INVALID_INTROSPECTION_REJECTION = auto()
