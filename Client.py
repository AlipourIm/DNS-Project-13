import socket
import time

from PrettyLogger import logger_config
import ssl

log = logger_config("client")


def establish_HTTPS_connection() -> socket.socket:
    sleep_time = 1
    while True:
        try:
            hostname = 'localhost'
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("./keys/certificate.pem")

            raw_sock = socket.create_connection((hostname, 443))
            tmp_https_socket = context.wrap_socket(raw_sock, server_hostname=hostname)

            log.info("Connected to Server successfully.")
            return tmp_https_socket

        except ConnectionRefusedError:
            log.warning(f"Server is not responding... retrying in {sleep_time}")
            time.sleep(sleep_time)
            sleep_time *= 2


if __name__ == "__main__":
    https_socket = establish_HTTPS_connection()
    https_socket.send("Hello? ".encode("ASCII"))
    try:
        while True:
            pass
    finally:
        https_socket.close()


