import logging
import pyqrcode  # type: ignore
import planet_auth_utils


def prompt_user(init_login_info):
    print("Please activate your device.")
    print(
        "Visit the activation site:\n"
        f"\n\t{init_login_info.get("verification_uri")}\n"
        "\nand enter the activation code:\n"
        f"\n\t{init_login_info.get("user_code")}\n"
    )

    # "verification_url_complete" is optional under the RFC.
    # This may not always be available to display.
    if init_login_info.get("verification_uri_complete"):
        qr_code = pyqrcode.create(content=init_login_info.get("verification_uri_complete"), error="L")
    else:
        qr_code = pyqrcode.create(content=init_login_info.get("verification_uri"), error="L")

    print(f"You may scan this QR code to continue with your mobile device:\n\n{qr_code.terminal()}\n")


def main():
    logging.basicConfig(level=logging.DEBUG)

    myapp_auth_client_config = {
        "client_type": "oidc_device_code",
        "auth_server": "https://login.example.com/",
        "client_id": "__client_id__",
        "scopes": ["planet", "offline_access", "openid", "profile"],
    }
    auth_ctx = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context_from_custom_config(
        client_config=myapp_auth_client_config,
        profile_name="_my_profile_name_",
        # This example directs the library to save the client configration to
        # a new profile, so that the application may bootstrap the auth session
        # from saved state.
        save_token_file=True,
        save_profile_config=True,
    )
    if not auth_ctx.request_authenticator_is_ready():
        login_init_info = auth_ctx.device_login_initiate()
        prompt_user(login_init_info)
        # credential will also be saved the file configured above, and
        # the request authenticator will be updated with the credential.
        credential = auth_ctx.device_login_complete(login_init_info)
        print(f"Credential saved to file {credential.path()}")


if __name__ == "__main__":
    main()
