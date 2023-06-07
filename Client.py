import datetime
import hashlib
import os
import socket
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import ElGamal
import RSA
import Resources
import User
from PrettyLogger import logger_config
import ssl

log = logger_config("client")

https_socket: socket.socket
user: User.User


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


def send_to_server(message, sign=False):
    global user
    message += Resources.SEP + str(datetime.datetime.now())
    signature = RSA.sign(message, RSA.pem_to_private_key(user.rsa_pr)) if sign else "NULL"
    message += Resources.SEP + signature
    https_socket.send(message.encode("ASCII"))


def register_new_user(username, password):
    global user
    if os.path.isdir(f"./user/{username}"):
        print("User already exists with this username.")
        return False
    rsa_pr, rsa_pk = RSA.gen_key(username, password)
    elgamal_pr, elgamal_pk = ElGamal.gen_key(username, password)
    password_hash = Resources.get_hash(password)
    message = f"register{Resources.SEP}" \
              f"{username}{Resources.SEP}" \
              f"{password_hash}{Resources.SEP}" \
              f"{rsa_pk}{Resources.SEP}" \
              f"{elgamal_pk}{Resources.SEP}"
    send_to_server(message, sign=False)
    response = https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
    print(response[2])
    if response[0] == "200":
        user = create_user(username, password)
        return True
    return False


def create_user(username, password):
    rsa_pr, rsa_pk, elgamal_pr, elgamal_pk = Resources.load_keys(username, password, True)
    RSA.validate_keys(rsa_pr, rsa_pk)
    ElGamal.validate_keys(elgamal_pr, elgamal_pk)

    return User.User(username, Resources.get_hash(password), rsa_pk, elgamal_pk, rsa_pr, elgamal_pr)


def login_user(username, password):
    global user
    if not os.path.isdir(f"./user/{username}"):
        print("You don't have the keys for this username")
        return False
    try:
        user = create_user(username, password)
    except Resources.InvalidKeysException:
        print("Keys are not valid")
        return False
    message = f"login{Resources.SEP}" \
              f"{username}"
    send_to_server(message, False)
    response = https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)

    if response[0] == "200":
        salt = response[2]
        password_hash = Resources.get_hash(password)
        otp = Resources.get_hash(salt + password_hash)
        message = f"{otp}"
        send_to_server(message, False)
        response = https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
        print(response[2])
        return response[0] == "200"
    else:
        return False


def retrieve_usernames_from_server():
    message = f"show users list"
    send_to_server(message, True)
    response = https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
    print(response[2])


def logout():
    global user

    message = "logout"
    send_to_server(message, True)

    response = https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
    print(response[2])

    user = None
    return


def user_menu():
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')

        print("  1: show users list\n"
              "  2: open chat <username>\n"
              "  3: open group <group_name>\n"
              "  4: create group <group_name>\n"
              "  5: logout")
        command = input("  > ").split()
        if command[0] == "show":
            retrieve_usernames_from_server()
        elif command[0] == "open" and command[1] == "chat":
            pass
        elif command[0] == "open" and command[1] == "group":
            pass
        elif command[0] == "create":
            pass
        elif command[0] == "logout":
            logout()
            return
        else:
            print("Wrong command!")


def main_menu():
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')

        print("  1: register <username> <password>\n"
              "  2: login <username> <password>")
        command = input("  > ").split()
        if command[0] == "register" and len(command) == 3:
            if register_new_user(command[1], command[2]):
                user_menu()
        elif command[0] == "login" and len(command) == 3:
            if login_user(command[1], command[2]):
                user_menu()
        else:
            print("Wrong command!")


if __name__ == "__main__":
    https_socket = establish_HTTPS_connection()
    try:
        main_menu()
    finally:
        https_socket.close()
