import logging
import planet_auth_utils


def main():
    logging.basicConfig(level=logging.DEBUG)
    auth_ctx = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context(auth_profile_opt="my-custom-profile")

    if not auth_ctx.request_authenticator_is_ready():
        # Returned credential is also saved to disk in the profile directory.
        credential = auth_ctx.login(allow_open_browser=True, allow_tty_prompt=True)
        print(f"New credential saved to file {format(credential.path())}")
    else:
        print(f"{auth_ctx.profile_name()} has already been initialized.")


if __name__ == "__main__":
    main()
