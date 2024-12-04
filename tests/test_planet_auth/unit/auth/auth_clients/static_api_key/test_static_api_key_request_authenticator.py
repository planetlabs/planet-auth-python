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

import unittest

from planet_auth.static_api_key.request_authenticator import FileBackedApiKeyRequestAuthenticator
from planet_auth.static_api_key.static_api_key import FileBackedApiKey
from planet_auth.util import FileBackedJsonObjectException
from tests.test_planet_auth.util import tdata_resource_file_path


class StaticApiKeyRequestAuthenticatorTest(unittest.TestCase):
    def test_pre_request_hook_loads_from_file_happy_path(self):
        under_test = FileBackedApiKeyRequestAuthenticator(
            api_key_credential=FileBackedApiKey(
                api_key_file=tdata_resource_file_path("keys/static_api_key_test_credential.json")
            )
        )
        under_test.pre_request_hook()
        self.assertEqual("test_api_key", under_test._token_body)
        self.assertEqual("test_prefix", under_test._token_prefix)

    def test_pre_request_hook_loads_from_file_invalid_throws(self):
        under_test = FileBackedApiKeyRequestAuthenticator(
            api_key_credential=FileBackedApiKey(
                api_key_file=tdata_resource_file_path("keys/invalid_test_credential.json")
            )
        )
        with self.assertRaises(FileBackedJsonObjectException):
            under_test.pre_request_hook()
