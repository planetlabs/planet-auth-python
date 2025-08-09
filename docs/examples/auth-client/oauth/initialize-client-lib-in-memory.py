import planet_auth_utils


def main():
    # The required fields will vary by client type.
    # See documentation regarding auth client configuration.
    auth_client_config = {
        "client_type": "oidc_auth_code",
        "auth_server": "https://login.example.com/",
        "client_id": "your_client_id",
        "local_redirect_uri": "http://localhost:8080",
        "audiences": ["https://api.planet.com/"],
        "scopes": ["offline_access", "openid", "profile", "planet"],
    }
    auth_ctx = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
        client_config=auth_client_config,
        profile_name="_my_profile_name_",
        save_token_file=False,
        save_profile_config=False,
    )
    print(
        f"Auth context initialized from in memory profile. Auth client class is {auth_ctx.auth_client().__class__.__name__}."
    )


if __name__ == "__main__":
    main()
