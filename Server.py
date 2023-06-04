import socket
import ssl
import threading

from PrettyLogger import logger_config

log = logger_config("webserver")


def establish_https_connection() -> socket.socket:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='./keys/certificate.pem', keyfile="./keys/key.pem")

    server_socket = context.wrap_socket(server_socket, server_side=True)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # This solves address already in use issue

    server_socket.bind(('localhost', 443))
    server_socket.listen(5)

    log.info("Server is listening on localhost:443")

    return server_socket


def client_handler(client, address):
    log.info(f"Client with address {address} connected.")

    try:
        while True:
            buffer = client.recv(1024).decode("ascii")
            log.info(f"message from client: {buffer.encode('ascii')}")

            arr = buffer.split("\r\n\r\n", maxsplit=4)
            arr[1] = arr[1]
    except KeyboardInterrupt:
        client.close()
        log.info(f"Client with address {address} disconnected.")
    except IndexError:
        client.close()
        log.info(f"Client with address {address} disconnected.")


def https_client_handler(https_socket: socket.socket):
    try:
        while True:
            client, address = https_socket.accept()
            handler_thread = threading.Thread(target=client_handler, args=(client, address))
            handler_thread.start()
    except KeyboardInterrupt:
        log.warning("terminating server")
        https_socket.close()


def main():
    https_socket = establish_https_connection()

    xclient_handler_thread = threading.Thread(target=https_client_handler, args=(https_socket,))
    xclient_handler_thread.start()


if __name__ == "__main__":
    main()
