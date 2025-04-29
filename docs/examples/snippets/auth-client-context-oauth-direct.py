import planet_auth_utils

auth_ctx = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
    client_config={
        "client_type": "oidc_auth_code",
        "auth_server": "https://login.example.com/",
        "client_id": "your_client_id",
        "redirect_uri": "client_redirect_url_for_network_hosted_handler__if_needed",
        "authorization_callback_acknowledgement": "optional__custom_authorization_callback_acknowledgement",
        "authorization_callback_acknowledgement_file": "optional__custom_authorization_callback_acknowledgement_from_a_file",
        "scopes": ["planet", "offline_access", "openid", "profile"],
    },
    profile_name="_my_profile_name_",
)
