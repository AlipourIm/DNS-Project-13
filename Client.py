import socket
import time

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


def register_new_user():
    pass


def retrieve_online_usernames_from_server():
    pass


def user_menu():
    while True:
        print("  1: show online users\n"
              "  2: open chat <username>\n"
              "  3: open group <group_name>\n"
              "  4: create group <group_name>\n")
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
        print("  1: register <username> <password>\n"
              "  2: login <username> <password>")
        command = input("  > ").split()
        if command[0] == "register":
            if register_new_user():
                user_menu()
        elif command[0] == "login":
            pass
        else:
            print("Wrong command!")


if __name__ == "__main__":
    https_socket = establish_HTTPS_connection()
    https_socket.send("Hello? ".encode("ASCII"))
    try:
        main_menu()
    finally:
        https_socket.close()
