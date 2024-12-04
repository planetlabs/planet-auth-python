from planet_auth import Auth


def main():
    # The required files will vary by client type
    auth_client_config = {
        "client_type": "oidc_auth_code",
        "auth_server": "https://account-next.planet.com/oauth2/planet",
        "client_id": "your_client_id",
        "redirect_uri": "https://static.prod.planet-labs.com/authentication-handler/live/main/",
        "local_redirect_uri": "http://localhost:8080",
        "audiences": ["https://api.staging.planet-labs.com/"],
        "scopes": ["offline_access", "openid", "profile", "planet"],
    }
    auth_ctx = Auth.initialize_from_config_dict(client_config=auth_client_config)
    print(
        "Auth context initialized from in memory profile. Auth client class is {}.".format(
            auth_ctx.auth_client().__class__.__name__
        )
    )


if __name__ == "__main__":
    main()
