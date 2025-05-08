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

import base64
import hashlib
import secrets

_DEFAULT_LENGTH = 96


def generate_nonce(length):
    return "".join([str(secrets.randbelow(10)) for i in range(length)])


def create_challenge(v):
    code_challenge = hashlib.sha256(v.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")
    return code_challenge


def create_verifier(length=_DEFAULT_LENGTH):
    code_verifier = secrets.token_urlsafe(length)
    return code_verifier


def create_pkce_challenge_verifier_pair(length=_DEFAULT_LENGTH):
    v = create_verifier(length)
    c = create_challenge(v)
    return v, c
