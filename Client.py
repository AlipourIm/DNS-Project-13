import datetime
import json
import os
import socket
import time
from typing import List, Dict

import AES
import ElGamal
import RSA
import Resources
import SecureSocket
from User import User
from PrettyLogger import logger_config
import ssl

log = logger_config("client")

https_socket: socket.socket
client_user: User
users: List[User] = []
messages: Dict[str, List[str]] = {}
server_public_key = None


def establish_HTTPS_connection() -> socket.socket:
    global server_public_key
    sleep_time = 1
    while True:
        try:
            hostname = 'localhost'
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("./keys/certificate.pem")
            with open("./keys/rsa_public.pem") as f:
                server_public_key = RSA.pem_to_public_key(f.read())

            sock = socket.create_connection((hostname, 12346))
            sock = SecureSocket.wrap_socket(sock)
            sock.establish_client(server_public_key)

            log.info("Connected to Server successfully.")
            return sock

        except ConnectionRefusedError:
            log.warning(f"Server is not responding... retrying in {sleep_time}")
            time.sleep(sleep_time)
            sleep_time *= 2


def send_to_server(message, sign=False):
    global client_user
    message += Resources.SEP + str(datetime.datetime.now())
    signature = RSA.sign(message, RSA.pem_to_private_key(client_user.rsa_pr)) if sign else "NULL"
    message += Resources.SEP + signature
    https_socket.send(message.encode("ASCII"))
    return


def receive_from_server():
    return https_socket.recv(Resources.BUFFER_SIZE).decode("ASCII")


def register_new_user(username, password):
    global client_user
    if os.path.isdir(f"./user/{username}"):
        print("User already exists with this username.")
        return False
    rsa_pr, rsa_pk = RSA.gen_key(username, password)
    elgamal_pr, elgamal_pk = ElGamal.gen_key(username, password)
    prekey_pr, prekey_pk = ElGamal.gen_key(username, password, "prekey")
    password_hash = Resources.get_hash(password)
    message = f"register{Resources.SEP}" \
              f"{username}{Resources.SEP}" \
              f"{password_hash}{Resources.SEP}" \
              f"{rsa_pk}{Resources.SEP}" \
              f"{elgamal_pk}{Resources.SEP}" \
              f"{prekey_pk}{Resources.SEP}"
    send_to_server(message, sign=False)
    response = receive_from_server().split(Resources.SEP)
    print(response[2])
    if response[0] == "200":
        client_user = create_user(username, password)
        return True
    return False


def create_user(username, password):
    rsa_pr, rsa_pk, elgamal_pr, elgamal_pk, prekey_pr, prekey_pk = Resources.load_keys(username, password, True)
    RSA.validate_keys(rsa_pr, rsa_pk)
    ElGamal.validate_keys(elgamal_pr, elgamal_pk)

    return User(username, Resources.get_hash(password), rsa_pk, elgamal_pk, prekey_pk, rsa_pr, elgamal_pr, prekey_pr)


def login_user(username, password):
    global client_user
    if not os.path.isdir(f"./user/{username}"):
        print("You don't have the keys for this username")
        return False
    try:
        client_user = create_user(username, password)
    except Resources.InvalidKeysException:
        print("Keys are not valid")
        return False
    except Resources.WrongPasswordException:
        print("Wrong password or keys are manipulated")
        return False
    message = f"login{Resources.SEP}" \
              f"{username}"
    send_to_server(message, False)
    response = receive_from_server().split(Resources.SEP)

    if response[0] == "200":
        salt = response[2]
        password_hash = Resources.get_hash(password)
        otp = Resources.get_hash(salt + password_hash)
        message = f"{otp}"
        send_to_server(message, False)
        response = receive_from_server().split(Resources.SEP)
        print(response[2])
        return response[0] == "200"
    else:
        return False


def retrieve_usernames_from_server():
    message = f"show users list"
    send_to_server(message, True)
    response = receive_from_server().split(Resources.SEP)
    print(response[2])


def logout():
    global client_user, users, messages

    message = "logout"
    send_to_server(message, True)

    response = receive_from_server().split(Resources.SEP)
    print(response[2])

    client_user = None
    users = []
    messages = {}
    return


def x3dh_key_exchange(target_user: User, seq=0) -> bool:
    ek_pr, ek_pk = ElGamal.gen_key()

    DH1 = ElGamal.DH_key(target_user.prekey_pk, client_user.elgamal_pr)
    DH2 = ElGamal.DH_key(target_user.elgamal_pk, ek_pr)
    DH3 = ElGamal.DH_key(target_user.prekey_pk, ek_pr)

    SK = AES.generate_symmetric_key(str(DH1) + str(DH2) + str(DH3))
    print("Generated SK =", SK)

    initial_message = str(client_user.elgamal_pk) + Resources.SEP \
                      + str(ek_pk) + Resources.SEP \
                      + str(target_user.prekey_pk)

    request = f"x3dh{Resources.SEP}" \
              f"{client_user.username}{Resources.SEP}" \
              f"{target_user.username}{Resources.SEP}" \
              f"{seq}{Resources.SEP}" \
              f"{RSA.sign(initial_message, RSA.pem_to_private_key(client_user.rsa_pr))}{Resources.SEP}" \
              f"{initial_message}"

    send_to_server(request, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3-1)
    return response[0] == "200"


def x3dh_extract_key(text: str):
    A_elgamal_pk, A_ek_pk, prekey_pk = list(map(int, text.split(Resources.SEP)))

    DH1 = ElGamal.DH_key(A_elgamal_pk, client_user.prekey_pr)
    DH2 = ElGamal.DH_key(A_ek_pk, client_user.elgamal_pr)
    DH3 = ElGamal.DH_key(A_ek_pk, client_user.prekey_pr)

    SK = AES.generate_symmetric_key(str(DH1) + str(DH2) + str(DH3))
    return SK


def retrieve_keys(username: str):
    message = f"retrieve keys{Resources.SEP}" \
              f"{username}"
    send_to_server(message, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3 - 1)

    if response[0] == "200":
        rsa_pk, elgamal_pk, prekey_pk = response[2].split(Resources.SEP)
        user = User(username, "", rsa_pk, int(elgamal_pk), int(prekey_pk))
        users.append(user)
        messages[user.username] = []
        return True
    else:
        print(response[2])
        return False


def fetch_messages():
    request = "fetch"
    send_to_server(request, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3-1)
    new_messages = json.loads(response[2])
    new_messages_lists = [message.split(Resources.SEP) for message in new_messages]
    new_messages_lists.sort(key=lambda x: x[3])

    for message in new_messages:
        _type, source_username, target_username, seq, signature, text = message.split(Resources.SEP, maxsplit=6-1)
        retrieve_keys(source_username)

        if _type == "x3dh":
            SK = x3dh_extract_key(text)
            print("Extracted SK =", SK)
            messages[source_username].append(_type + Resources.SEP + SK)
        else:
            messages[source_username].append(_type + Resources.SEP + text)


def open_chat(username: str) -> bool:
    if client_user.username == username:
        print("You cannot send message you yourself.")
        return False

    fetch_messages()

    for user in users:
        if user.username == username:
            print("blah blah blah")
            return True

    # Let's do the magic!
    if retrieve_keys(username):
        for user in users:
            if user.username == username:
                x3dh_key_exchange(user)
        return True

    return False


def user_menu():
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Welcome {client_user.username}.\n")
        print("  1: show users list\n"
              "  2: open chat <username>\n"
              "  3: open group <group_name>\n"
              "  4: create group <group_name>\n"
              "  5: logout")
        command = input("  > ").split()
        if command[0] == "show":
            retrieve_usernames_from_server()
        elif command[0] == "open" and command[1] == "chat":
            if open_chat(command[2]):
                # chat_menu()
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
