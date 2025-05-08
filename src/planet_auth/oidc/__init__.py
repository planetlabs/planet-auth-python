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

"""
Package providing an OAuth2/OIDC implementation of the planet_auth package
interfaces.  This is a generic OAuth2/OIDC auth client, and knows nothing
about Planet APIs.

AuthClients are provided for a number of authentication flows, suitable
for user interactive or headless use cases.

Several Request Authenticators are provided that can use the OIDC credentials
obtained from an AuthClient.  Since frequent credential refresh is a part of
using OAuth2/OIDC, these authenticators handle this transparently.
"""
