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

import asyncio
import cryptography.hazmat.primitives.serialization as crypto_serialization
import importlib.resources
import os
import socket
import sys

from contextlib import closing

from planet_auth.auth_client import AuthClientConfig


def is_interactive_shell() -> bool:
    return sys.stdin.isatty()


def is_not_interactive_shell() -> bool:
    return not sys.stdin.isatty()


def is_cicd() -> bool:
    # CI - GitHub
    # CI_COMMIT_SHA - GitLab
    return bool(os.getenv("CI") or os.getenv("CI_COMMIT_SHA"))


def tdata_resource_file_path(resource_file: str):
    file_path = importlib.resources.files("tests.test_planet_auth").joinpath("data/" + resource_file)
    return file_path


def load_auth_client_config(named_config):
    sops_path = tdata_resource_file_path("auth_client_configs/{}.sops.json".format(named_config))
    clear_path = tdata_resource_file_path("auth_client_configs/{}.json".format(named_config))
    if sops_path.is_file():
        conf_path = sops_path
    else:
        conf_path = clear_path
    return AuthClientConfig.from_file(conf_path)


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def load_rsa_private_key(key_file_path, password=None):
    with open(key_file_path, "rb") as key_file:
        if password:
            encoded_password = password.encode()
        else:
            encoded_password = None

        priv_key = crypto_serialization.load_pem_private_key(key_file.read(), password=encoded_password)
        if not priv_key:
            raise RuntimeError("Could not load private key from {}".format(key_file_path))

    return priv_key


def background(f):
    from functools import wraps

    @wraps(f)
    def wrapped(*args, **kwargs):
        loop = asyncio.get_event_loop()
        if callable(f):
            return loop.run_in_executor(None, f, *args, **kwargs)
        else:
            raise TypeError("Task must be a callable")

    return wrapped


def mock_sleep_skip(seconds):
    pass


class FreezeGunMockSleep:
    def __init__(self, frozen_time):
        self.frozen_time = frozen_time

    def mock_sleep(self, seconds):
        self.frozen_time.tick(seconds)
