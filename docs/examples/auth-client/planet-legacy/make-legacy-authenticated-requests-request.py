import requests

import planet_auth
import planet_auth_config  # type: ignore


def main():
    _legacy_client_config = {
        **planet_auth_config.Staging.LEGACY_AUTH_AUTHORITY,
        "client_type": "planet_legacy",
    }

    auth_ctx = planet_auth.Auth.initialize_from_config_dict(
        client_config=_legacy_client_config, token_file="/saved_token.json"
    )
    # The presumption in this example is that the login has already been performed and the token saved.
    # See the login example for that process.

    result = requests.get(url="https://api.planet.com/basemaps/v1/mosaics", auth=auth_ctx.request_authenticator())
    print(result.status_code)
    print(result.json())


if __name__ == "__main__":
    main()
