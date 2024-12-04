from planet_auth import Auth


def main():
    auth_ctx = Auth.initialize_from_profile(profile="my-custom-profile")
    print("Auth context initialized from on disk profile {}".format(auth_ctx.profile_name()))


if __name__ == "__main__":
    main()
