import planet_auth
import planet_auth_config  # type: ignore


def main():
    _legacy_client_config = {
        **planet_auth_config.Staging.LEGACY_AUTH_AUTHORITY,
        "client_type": "planet_legacy",
    }
    # Be careful where you save the token file
    auth_ctx = planet_auth.Auth.initialize_from_config_dict(
        client_config=_legacy_client_config, token_file="/saved_token.json"
    )
    auth_ctx.login(allow_tty_prompt=True)


if __name__ == "__main__":
    main()
