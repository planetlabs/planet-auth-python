import planet_auth_utils


def main():
    auth_ctx = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context(auth_profile_opt="my-custom-profile")
    print("Auth context initialized from on disk profile {}".format(auth_ctx.profile_name()))


if __name__ == "__main__":
    main()
