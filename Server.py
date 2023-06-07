import datetime
import os
import random
import socket
import ssl
import threading

import RSA
from User import User
from PrettyLogger import logger_config
import Resources

log = logger_config("webserver")
users = []


def verify_timestamp(timestamp):
    event_time = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
    if not (-datetime.timedelta(minutes=1) < event_time - datetime.datetime.now() < datetime.timedelta(minutes=1)):
        raise Resources.NotFreshException


def receive_from_client(client_socket, user: User):
    response = client_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
    signature = response[-1]
    timestamp = response[-2]
    signed_message = Resources.SEP.join(response[:-1])
    original_message = Resources.SEP.join(response[:-2])

    verify_timestamp(timestamp)

    if user is not None:
        RSA.verify_signature(signed_message, signature, RSA.pem_to_public_key(user.rsa_pk))

    return original_message


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
    log.info(f"message to client: {response.encode('ASCII')}")


def register_new_user(client_socket, username, password_hash, rsa_pk, elgamal_pk):
    for user in users:
        if user.username == username:
            response = f"400{Resources.SEP}" \
                       f"Bad Request{Resources.SEP}" \
                       f"Username already exists"
            response_client(client_socket, response)
            return

    new_user = User(username, password_hash, rsa_pk, elgamal_pk)
    users.append(new_user)
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"User registered successfully"
    response_client(client_socket, response)
    return new_user


def login_user(client_socket, username):
    for user in users:
        if username == user.username:
            salt = random.randint(0, 10 ** 50)
            response = f"200{Resources.SEP}" \
                       f"OK{Resources.SEP}" \
                       f"{salt}"
            response_client(client_socket, response)
            otp = receive_from_client(client_socket, None)

            if user.check_password(str(salt), otp):
                response = f"200{Resources.SEP}" \
                           f"OK{Resources.SEP}" \
                           f"User {user.username} logged in " \
                           f"successfully"
                response_client(client_socket, response)
                user.set_online()
                return user

            else:
                response = f"400{Resources.SEP}" \
                           f"Bad Request{Resources.SEP}" \
                           f"Wrong password"
                response_client(client_socket, response)
                return None

    response = f"400{Resources.SEP}" \
               f"Bad Request{Resources.SEP}" \
               f"User does not exist"
    response_client(client_socket, response)
    return None


def logout_user(client_socket, user: User):
    user.set_offline()
    response = f"200{Resources.SEP}" \
               f"OK{Resources.SEP}" \
               f"Goodbye!"
    response_client(client_socket, response)
    return None


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
            buffer = receive_from_client(client, user)
            log.info(f"message from client: {buffer.encode('ASCII')}")

            arr = buffer.split(Resources.SEP)

            if len(buffer) == 0:
                raise IndexError

            if arr[0] == "register":
                user = register_new_user(client, arr[1], arr[2], arr[3], arr[4])
            elif arr[0] == "show users list":
                show_users_list(client)
            elif arr[0] == "login":
                user = login_user(client, arr[1])
            elif arr[0] == "logout":
                user = logout_user(client, user)

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
