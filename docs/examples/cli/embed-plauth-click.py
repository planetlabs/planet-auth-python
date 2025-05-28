import click
import logging
import requests

import planet_auth_utils

logging.basicConfig(level=logging.DEBUG)

# TODO: This example does not show how the application may use built-in profile
#     dependency injection to provide a smooth user experience when using an
#     OAuth sevice account that is defined by a client ID and client secret.


@click.group(help="my cli main help message")
@planet_auth_utils.opt_profile
@planet_auth_utils.opt_client_id()
@planet_auth_utils.opt_client_secret()
@click.pass_context
def my_cli_main(ctx, auth_profile, auth_client_id, auth_client_secret):
    ctx.ensure_object(dict)
    ctx.obj["AUTH"] = planet_auth_utils.PlanetAuthFactory.initialize_auth_client_context(
        auth_profile_opt=auth_profile,
        auth_client_id_opt=auth_client_id,
        auth_client_secret_opt=auth_client_secret,
    )


@my_cli_main.command("cmd1", help="cmd1 help message")
@click.pass_context
def do_cmd1(ctx):
    auth_ctx = ctx.obj["AUTH"]
    print("Doing cmd1 with the auth profile '{}'".format(auth_ctx.profile_name()))
    result = requests.get(
        url="http://localhost:5001/",  # flask example service.
        auth=auth_ctx.request_authenticator(),
        timeout=30,
    )
    print("Status: {}".format(result.status_code))
    print("Payload:\n{}".format(result.text))


@my_cli_main.command("cmd2", help="cmd2 help message")
@click.pass_context
def do_cmd2(ctx):
    auth_ctx = ctx.obj["AUTH"]
    print("Doing cmd2 with the auth profile '{}'".format(auth_ctx.profile_name()))
    result = requests.get(
        url="http://localhost:5001/secret",  # flask example service.
        auth=auth_ctx.request_authenticator(),
        timeout=30,
    )
    print("Status: {}".format(result.status_code))
    print("Payload:\n{}".format(result.text))


my_cli_main.add_command(planet_auth_utils.cmd_plauth_embedded)

if __name__ == "__main__":
    my_cli_main()  # pylint: disable=E1120
