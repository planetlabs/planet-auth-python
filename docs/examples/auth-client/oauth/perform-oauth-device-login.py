import logging
import pyqrcode # type: ignore
from planet_auth import Auth


def prompt_user(init_login_info):
    print("Please activate your device.")
    print(
        "Visit the activation site:\n"
        "\n\t{}\n"
        "\nand enter the activation code:\n"
        "\n\t{}\n".format(init_login_info.get("verification_uri"), init_login_info.get("user_code"))
    )
    if init_login_info.get("verification_uri_complete"):  # "verification_url_complete" is optional under the RFC.
        qr_code = pyqrcode.create(content=init_login_info.get("verification_uri_complete"), error="L")
        print(
            "Or, scan the QR code with your mobile device to visit {}:\n\n{}\n".format(
                init_login_info.get("verification_uri_complete"), qr_code.terminal()
            )
        )


def main():
    logging.basicConfig(level=logging.DEBUG)
    # In memory initialization.
    # Profiles can also be used with "device code" client types.
    auth_ctx = Auth.initialize_from_config_dict(
        client_config={
            "client_type": "oidc_device_code",
            "auth_server": "__auth_server__",
            "client_id": "__client_id__",
            "scopes": ["planet", "offline_access", "openid", "profile"],
        },
        token_file="/secure_device_storage/device_token.json",
    )

    login_init_info = auth_ctx.device_login_initiate()
    prompt_user(login_init_info)
    # credential will also be saved the file configured above, and
    # the request authenticator will be updated with the credential.
    credential = auth_ctx.device_login_complete(login_init_info)
    print(f"Credential saved to file {credential.path()}")


if __name__ == "__main__":
    main()
