import logging
from planet_auth import Auth


def main():
    logging.basicConfig(level=logging.DEBUG)
    auth_ctx = Auth.initialize_from_profile(profile="my-custom-profile")
    credential = auth_ctx.login()  # Returned credential is also saved to disk in the profile directory.
    print("Credential saved to file {}".format(credential.path()))


if __name__ == "__main__":
    main()
