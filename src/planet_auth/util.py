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

from typing import Dict, Optional

import planet_auth.logging.auth_logger

auth_logger = planet_auth.logging.auth_logger.getAuthLogger()


def parse_content_type(content_type: Optional[str]) -> Dict[str, Optional[str]]:
    result: Dict[str, Optional[str]] = {
        "content-type": None,
    }
    if content_type:
        ct = content_type.split(";")
        result["content-type"] = ct.pop(0).strip()
        if not result["content-type"]:
            # Don't return blank strings
            result["content-type"] = None
        for subfield in ct:
            sf = subfield.split("=", 1)
            if sf[0].strip():
                if len(sf) == 1:
                    result[sf[0].strip()] = None
                else:
                    result[sf[0].strip()] = sf[1].strip()
    return result


def custom_json_class_dumper(obj):
    try:
        return obj.__json_pretty_dumps__()
    except Exception:
        return obj
