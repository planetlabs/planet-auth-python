import logging
import httpx
from planet_auth import Auth


def main():
    logging.basicConfig(level=logging.DEBUG)
    auth_ctx = Auth.initialize_from_profile(profile="my-custom-profile")
    result = httpx.get(
        url="https://api.planet.com/basemaps/v1/mosaics",
        auth=auth_ctx.request_authenticator(),
        headers={"X-Planet-App": "httpx-example"},
    )
    print(result.status_code)
    print(result.json())


if __name__ == "__main__":
    main()
