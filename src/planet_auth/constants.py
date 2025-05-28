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

import importlib.metadata

AUTH_CONFIG_FILE_PLAIN = "auth_client.json"
AUTH_CONFIG_FILE_SOPS = "auth_client.sops.json"
TOKEN_FILE_PLAIN = "token.json"
TOKEN_FILE_SOPS = "token.sops.json"
USER_CONFIG_FILE = ".planet.json"
PROFILE_DIR = ".planet"
X_PLANET_APP = f"planet-auth-library-{importlib.metadata.version('planet-auth')}"
X_PLANET_APP_HEADER = "X-Planet-App"
