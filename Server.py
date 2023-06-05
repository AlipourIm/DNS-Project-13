import os
import socket
import ssl
import threading

from User import User
from PrettyLogger import logger_config
import Resources

log = logger_config("webserver")
users = []


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


def response_client(client_socket, response):
    client_socket.send(response.encode("ASCII"))
    log.info(f"message to client: {response}")


def register_new_user(client_socket, username, password, rsa_pk, elgamal_pk):
    for user in users:
        if user.username == username:
            response = f"400{Resources.SEP}" \
                       f"Bad Request{Resources.SEP}" \
                       f"Username already exists"
            response_client(client_socket, response)
            return

    new_user = User(username, password, rsa_pk, elgamal_pk)
    users.append(new_user)
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"User registered successfully"
    response_client(client_socket, response)
    return new_user


def show_users_list(client_socket):
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}"

    for user in users:
        response += f"- {user.username} ({'Online' if user.is_online else 'Offline'})\n"

    response_client(client_socket, response[:-1])
    return


def client_handler(client, address):
    log.info(f"Client with address {address} connected.")
    user = None

    try:
        while True:
            buffer = client.recv(Resources.BUFFER_SIZE).decode("ascii")
            log.info(f"message from client: {buffer.encode('ascii')}")

            arr = buffer.split(Resources.SEP)

            if len(buffer) == 0:
                raise IndexError

            if arr[0] == "register":
                user = register_new_user(client, arr[1], arr[2], arr[3], arr[4])
            elif arr[0] == "show users list":
                show_users_list(client)

    except (KeyboardInterrupt, IndexError):
        client.close()
        if user is not None:
            user.set_offline()
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
    https_client_handler(https_socket)


if __name__ == "__main__":
    main()
