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

import unittest
import importlib.resources

from planet_auth.oidc import resources as planet_auth_oidc_resources


class TestResources(unittest.TestCase):
    def test_can_read_oidc_resources(self):
        # I've broken resource packaging so many times....
        # This is best run against an installed dist package.
        # Running against the local dev tree doesn't catch
        # all problems (like a missed MANIFEST.in file)
        under_test = (
            importlib.resources.files(planet_auth_oidc_resources)
            .joinpath("callback_acknowledgement.html")
            .read_text("utf-8")
        )
        self.assertIsNotNone(under_test)
