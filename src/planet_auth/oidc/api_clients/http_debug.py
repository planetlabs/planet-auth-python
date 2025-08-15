import http
import logging


def log_response(response):
    logging.debug(
        f'{"-"*9} BEGIN Received {"-"*9}\n'
        f"Status: {response.status_code}\n\n"
        f"Headers:\n{response.headers}\n\n"
        f"Body:\n{response.text}\n"
        f'{"-"*9} END Received {"-"*9}'
    )


def patch_send():
    old_send = http.client.HTTPConnection.send

    def new_send(self, data):
        print(f'{"-"*9} BEGIN SEND {"-"*9}')
        print(data.decode("utf-8").strip())
        print(f'{"-"*10} END SEND {"-"*10}')
        return old_send(self, data)

    http.client.HTTPConnection.send = new_send


patch_send()  # This just enables this debug logging is imported, which is ugly.
