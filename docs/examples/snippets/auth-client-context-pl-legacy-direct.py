import planet_auth_utils

auth_ctx = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
    client_config={
        "client_type": "planet_legacy",
        "legacy_auth_endpoint": "https://api.planet.com/v0/auth/login",
        "api_key": "_optional_to_eliminate_need_to_do_login_",
    },
    profile_name="_my_legacy_profile_name_",
)
