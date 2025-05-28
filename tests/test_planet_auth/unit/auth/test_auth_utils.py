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
import planet_auth.util as auth_util


class ContentTypeParserTest(unittest.TestCase):
    def test_simple(self):
        result = auth_util.parse_content_type("application/json")
        self.assertEqual({"content-type": "application/json"}, result)

        result = auth_util.parse_content_type("\tapplication/json ")
        self.assertEqual({"content-type": "application/json"}, result)

    def test_none(self):
        result = auth_util.parse_content_type(None)
        self.assertEqual({"content-type": None}, result)

    def test_blank(self):
        result = auth_util.parse_content_type("")
        self.assertEqual({"content-type": None}, result)

        result = auth_util.parse_content_type("   ")
        self.assertEqual({"content-type": None}, result)

    def test_extra_fields_1(self):
        result = auth_util.parse_content_type("application/json; charset=utf-8")
        self.assertEqual({"content-type": "application/json", "charset": "utf-8"}, result)

        result = auth_util.parse_content_type("\tapplication/json  ;;; charset = utf-8\t")
        self.assertEqual({"content-type": "application/json", "charset": "utf-8"}, result)

    def test_extra_fields_2(self):
        result = auth_util.parse_content_type("application/json; extra1")
        self.assertEqual({"content-type": "application/json", "extra1": None}, result)

        result = auth_util.parse_content_type("\tapplication/json  ;;; extra1\t")
        self.assertEqual({"content-type": "application/json", "extra1": None}, result)
