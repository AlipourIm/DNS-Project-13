import os
import socket
import time

import ElGamal
import RSA
import Resources
from PrettyLogger import logger_config
import ssl

log = logger_config("client")

https_socket: socket.socket


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


def register_new_user(username, password):
    # TODO: gen_key() both ElGamal & RSA and send them to server along with our credentials
    if os.path.isdir(f"./user/{username}"):
        print("User already exists with this username.")
        return False
    rsa_pr, rsa_pk = RSA.gen_key(username)
    elgamal_pr, elgamal_pk = ElGamal.gen_key(username)
    message = f"register{Resources.SEP}" \
              f"{username}{Resources.SEP}" \
              f"{password}{Resources.SEP}" \
              f"{rsa_pk}{Resources.SEP}" \
              f"{elgamal_pk}{Resources.SEP}"
    https_socket.send(message.encode("ASCII"))
    response = https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII").split(Resources.SEP)
    print(response)
    if response[0] == "200":
        return True
    return False


def retrieve_online_usernames_from_server():
    pass


def user_menu():
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')

        print("  1: show online users\n"
              "  2: open chat <username>\n"
              "  3: open group <group_name>\n"
              "  4: create group <group_name>")
        command = input("  > ").split()
        if command[0] == "show":
            retrieve_online_usernames_from_server()
        elif command[0] == "open" and command[1] == "chat":
            pass
        elif command[0] == "open" and command[1] == "group":
            pass
        elif command[0] == "create":
            pass
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
        elif command[0] == "login":
            pass
        else:
            print("Wrong command!")


if __name__ == "__main__":
    https_socket = establish_HTTPS_connection()
    try:
        main_menu()
    finally:
        https_socket.close()
