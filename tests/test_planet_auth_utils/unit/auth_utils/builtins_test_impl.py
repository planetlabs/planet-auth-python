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

from typing import Dict, List, Optional
from planet_auth_config_injection import BuiltinConfigurationProviderInterface


class MockStagingEnv:
    PRIMARY_OAUTH_AUTHORITY_USERS = {
        "_comment": "OIDC/OAuth server used by Public API endpoints",
        "auth_server": "https://mock-login1.staging.utest.planet.com/",
        "audiences": ["https://mock-api.staging.utest.planet.com/"],
    }
    PRIMARY_OAUTH_AUTHORITY_M2M = {
        "_comment": "OIDC/OAuth server used by Public API endpoints",
        "auth_server": "https://mock-login2.staging.utest.com/auth/realms/m2m",
        "audiences": ["https://mock-api.staging.utest.planet.com/"],
    }
    LEGACY_AUTH_AUTHORITY = {
        "_comment": "Planet legacy JWT auth server used by Public API endpoints",
        "legacy_auth_endpoint": "https://mock-api.staging.utest.planet.com/v0/auth/login",
    }
    TRUSTED_OAUTH_AUTHORITIES = [PRIMARY_OAUTH_AUTHORITY_USERS, PRIMARY_OAUTH_AUTHORITY_M2M]


class MockProductionEnv:
    PRIMARY_OAUTH_AUTHORITY_USERS = {
        "_comment": "OIDC/OAuth server used by Public API endpoints",
        "auth_server": "https://mock-login1.prod.utest.planet.com/",
        "audiences": ["https://mock-api.prod.utest.planet.com/"],
    }
    PRIMARY_OAUTH_AUTHORITY_M2M = {
        "_comment": "OIDC/OAuth server used by Public API endpoints",
        "auth_server": "https://mock-login2.prod.utest.com/auth/realms/m2m",
        "audiences": ["https://mock-api.prod.utest.planet.com/"],
    }
    LEGACY_AUTH_AUTHORITY = {
        "_comment": "Planet legacy JWT auth server used by Public API endpoints",
        "legacy_auth_endpoint": "https://mock-api.prod.utest.planet.com/v0/auth/login",
    }
    TRUESTED_OAUTH_AUTHORITIES = [PRIMARY_OAUTH_AUTHORITY_USERS, PRIMARY_OAUTH_AUTHORITY_M2M]


_BUILTIN_USER_CLIENT_PROD = {
    **MockProductionEnv.PRIMARY_OAUTH_AUTHORITY_USERS,
    "client_type": "oidc_device_code",
    # "client_type": "oidc_auth_code",
    "client_id": "TestMocke5yWHbTxzgMX9nFfn6jaEVy3",
    # "local_redirect_uri": "http://localhost:8080",
    "scopes": ["test_scope", "offline_access", "openid", "profile", "email"],
}

_BUILTIN_M2M_CLIENT_PROD = {
    **MockProductionEnv.PRIMARY_OAUTH_AUTHORITY_M2M,
    "client_type": "oidc_client_credentials_secret",
    "scopes": [],
    # "client_id": "__MUST_BE_USER_SUPPLIED__",
    # "client_secret": "__MUST_BE_USER_SUPPLIED__",
    # "scopes": ["test_scope"],
    # "audiences": [""]
}

_BUILTIN_USER_CLIENT_STAGING = {
    **MockStagingEnv.PRIMARY_OAUTH_AUTHORITY_USERS,
    "client_type": "oidc_device_code",
    # "client_type": "oidc_auth_code",
    "client_id": "TestMockYvR5jTcidWMNFUKV9AXdT6hI",
    # "local_redirect_uri": "http://localhost:8080", #
    "scopes": ["test_scope", "offline_access", "openid", "profile", "email"],
}

_BUILTIN_M2M_CLIENT_STAGING = {
    **MockStagingEnv.PRIMARY_OAUTH_AUTHORITY_M2M,
    "client_type": "oidc_client_credentials_secret",
    "scopes": [],
    # "client_id": "__MUST_BE_USER_SUPPLIED__",
    # "client_secret": "__MUST_BE_USER_SUPPLIED__",
    # "scopes": ["test_scope"],
}

_BUILTIN_LEGACY_AUTH_CLIENT_PROD = {
    **MockProductionEnv.LEGACY_AUTH_AUTHORITY,
    "client_type": "planet_legacy",
}

_BUILTIN_LEGACY_AUTH_CLIENT_STAGING = {
    **MockStagingEnv.LEGACY_AUTH_AUTHORITY,
    "client_type": "planet_legacy",
}

_NOOP_AUTH_CLIENT_CONFIG = {
    "client_type": "none",
}


class BuiltinConfigurationProviderMockTestImpl(BuiltinConfigurationProviderInterface):
    # fmt: off
    ##
    ## OAuth production environment profiles
    ##
    # Real
    BUILTIN_PROFILE_NAME_UTEST_USER          = "utest-user"
    BUILTIN_PROFILE_NAME_UTEST_M2M           = "utest-m2m"
    BUILTIN_PROFILE_NAME_UTEST_USER_STAGING  = "utest-user-staging"
    BUILTIN_PROFILE_NAME_UTEST_M2M_STAGING   = "utest-m2m-staging"
    # Aliases
    BUILTIN_PROFILE_ALIAS_UTEST_PROD          = "utest-prod"
    BUILTIN_PROFILE_ALIAS_UTEST_M2M_PROD      = "utest-m2m-prod"
    BUILTIN_PROFILE_ALIAS_UTEST_AUTH0_PROD    = "utest-user-prod"

    ##
    ## Profiles that use Planet's old (pre-OAuth) based auth protocol
    ##
    BUILTIN_PROFILE_NAME_UTEST_LEGACY         = "utest-legacy"
    BUILTIN_PROFILE_NAME_UTEST_LEGACY_STAGING = "utest-legacy-staging"

    ##
    ## Misc auth profiles
    ##
    BUILTIN_PROFILE_NAME_NONE    = "none"
    BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_1 = "alias1"
    BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_2 = "alais2"

    ##
    ## Default that should be used when no other selection has been made
    ##
    DEFAULT_PROFILE = BUILTIN_PROFILE_NAME_UTEST_USER

    _builtin_profile_auth_client_configs = {
        ## OAuth Client Configs
        BUILTIN_PROFILE_NAME_UTEST_USER          : _BUILTIN_USER_CLIENT_PROD,
        BUILTIN_PROFILE_NAME_UTEST_M2M           : _BUILTIN_M2M_CLIENT_PROD,
        BUILTIN_PROFILE_NAME_UTEST_USER_STAGING  : _BUILTIN_USER_CLIENT_STAGING,
        BUILTIN_PROFILE_NAME_UTEST_M2M_STAGING   : _BUILTIN_M2M_CLIENT_STAGING,

        # Planet Legacy Protocols
        BUILTIN_PROFILE_NAME_UTEST_LEGACY            : _BUILTIN_LEGACY_AUTH_CLIENT_PROD,
        BUILTIN_PROFILE_NAME_UTEST_LEGACY_STAGING    : _BUILTIN_LEGACY_AUTH_CLIENT_STAGING,

        # Misc
        BUILTIN_PROFILE_NAME_NONE              : _NOOP_AUTH_CLIENT_CONFIG,
    }

    _builtin_profile_aliases = {
        BUILTIN_PROFILE_ALIAS_UTEST_PROD                : BUILTIN_PROFILE_NAME_UTEST_USER,
        BUILTIN_PROFILE_ALIAS_UTEST_M2M_PROD            : BUILTIN_PROFILE_NAME_UTEST_M2M,
        BUILTIN_PROFILE_ALIAS_UTEST_AUTH0_PROD          : BUILTIN_PROFILE_NAME_UTEST_USER,
        BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_1             : BUILTIN_PROFILE_NAME_UTEST_USER,
        BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_2             : BUILTIN_PROFILE_ALIAS_UTEST_ALIAS_1,
    }

    _builtin_profile_default_by_client_type = {
        "oidc_device_code"               : BUILTIN_PROFILE_NAME_UTEST_USER,
        "oidc_auth_code"                 : BUILTIN_PROFILE_NAME_UTEST_USER,
        "oidc_client_credentials_secret" : BUILTIN_PROFILE_NAME_UTEST_M2M,
        "planet_legacy"                  : BUILTIN_PROFILE_NAME_UTEST_LEGACY,
    }

    _builtin_trust_realms: Dict[str, Optional[List[dict]]] = {
        "STAGING": MockStagingEnv.TRUSTED_OAUTH_AUTHORITIES,
        "PRODUCTION": MockProductionEnv.TRUESTED_OAUTH_AUTHORITIES,
        "CUSTOM": None,
    }
    # fmt: on

    def builtin_client_authclient_config_dicts(self) -> Dict[str, dict]:
        return self._builtin_profile_auth_client_configs

    def builtin_client_profile_aliases(self) -> Dict[str, str]:
        return self._builtin_profile_aliases

    def builtin_default_profile_by_client_type(self) -> Dict[str, str]:
        return self._builtin_profile_default_by_client_type

    def builtin_default_profile(self) -> str:
        return self.DEFAULT_PROFILE

    def builtin_trust_environments(self) -> Dict[str, Optional[List[dict]]]:
        return BuiltinConfigurationProviderMockTestImpl._builtin_trust_realms
