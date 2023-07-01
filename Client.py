import copy
import datetime
import json
import os
import socket
import time
from getpass import getpass
from typing import List, Dict, Optional

from cryptography.exceptions import InvalidSignature

import AES
import ElGamal
import RSA
import Resources
import SecureSocket
from Chat import Chat
from Group import Group
from Message import Message
from User import User
from PrettyLogger import logger_config
import ssl

log = logger_config("client")

https_socket: socket.socket
client_user: Optional[User] = None
users: List[User] = []
groups: Dict[str, Group] = {}
# messages: Dict[str, List[Message]] = {}
chats: Dict[str, Chat] = {}
server_public_key = None


def dump_chat(chat):
    dumped_chat = {"root_key": chat.root_key,
                   "message_key": chat.message_key,
                   "DH_key": chat.DH_key,
                   "our_pr": chat.our_pr,
                   "their_pk": chat.their_pk,
                   "their_rsa_pk": chat.their_rsa_pk,
                   "seq": chat.seq,
                   "username": chat.username,
                   "messages": []}
    for message in chat.messages:
        dumped_chat["messages"].append({"source_rsa_pk": message.source_rsa_pk,
                                        "message_type": message.message_type,
                                        "source_username": message.source_username,
                                        "target_username": message.target_username,
                                        "seq": message.seq, "signature": message.signature,
                                        "text": message.text,
                                        "target_group": message.target_group
                                        })
    return dumped_chat


def load_chat(dumped_chat):
    username = dumped_chat["username"]
    chat = Chat(username)
    chat.root_key = dumped_chat["root_key"]
    chat.message_key = dumped_chat["message_key"]
    chat.DH_key = dumped_chat["DH_key"]
    chat.our_pr = dumped_chat["our_pr"]
    chat.their_pk = dumped_chat["their_pk"]
    chat.their_rsa_pk = dumped_chat["their_rsa_pk"]
    chat.seq = dumped_chat["seq"]
    chat.messages = []
    for message in dumped_chat["messages"]:
        new_message = Message(message["message_type"], message["source_username"], message["target_username"],
                              message["seq"], message["signature"], message["text"], message["target_group"])
        new_message.source_rsa_pk = message["source_rsa_pk"]
        chat.messages.append(new_message)
    return chat


def save_to_db():
    db = {"users": [], "chats": [], "groups": []}
    for user in users:
        new_user = {"rsa_pk": user.rsa_pk, "elgamal_pk": user.elgamal_pk, "prekey_pk": user.prekey_pk,
                    "username": user.username}
        db["users"].append(new_user)

    for username in chats:
        chat = chats[username]
        dumped_chat = dump_chat(chat)
        db["chats"].append(dumped_chat)

    for group_name in groups:
        group = groups[group_name]
        dumped_group = {"admin_username": group.admin_username,
                        "group_name": group_name,
                        "usernames": group.usernames}
        new_chat = dump_chat(group.chat)
        dumped_group["chat"] = new_chat
        db["groups"].append(dumped_group)

    with open(f"./user/{client_user.username}/{client_user.username}_db.imal", 'wb') as db_file:
        content = json.dumps(db)
        aes_key = AES.generate_symmetric_key(client_user.password_hash)
        db_encrypted = AES.encrypt(content, aes_key, AES.default_iv)
        db_file.write(db_encrypted.encode("ASCII"))


def load_db(username, password_hash):
    global users, chats

    with open(f"./user/{username}/{username}_db.imal", 'rb') as db_file:
        db_encrypted = db_file.read().decode("ASCII")
        aes_key = AES.generate_symmetric_key(password_hash)
        content = AES.decrypt(db_encrypted, aes_key, AES.default_iv)
        db = json.loads(content)

    for dumped_user in db["users"]:
        user = User(dumped_user["username"], dumped_user["rsa_pk"], "",
                    dumped_user["elgamal_pk"], dumped_user["prekey_pk"])
        users.append(user)

    for dumped_chat in db["chats"]:
        chat = load_chat(dumped_chat)
        chats[chat.username] = chat

    for dumped_group in db["groups"]:
        group = Group(dumped_group["admin_username"], dumped_group["group_name"])
        group.usernames = dumped_group["usernames"]
        group.chat = load_chat(dumped_group["chat"])
        groups[group.group_name] = group


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
    message_type = "register"
    return initialize_user(message_type, username, password)


def initialize_user(message_type: str, username: str, password: str, old_password_hash="") -> bool:
    global client_user
    rsa_pr, rsa_pk = RSA.gen_key(username, password)
    elgamal_pr, elgamal_pk = ElGamal.gen_key(username, password)
    prekey_pr, prekey_pk = ElGamal.gen_key(username, password, "prekey")
    password_hash = Resources.get_hash(username + password)
    second_field = username if message_type == "register" else old_password_hash
    message = f"{message_type}{Resources.SEP}" \
              f"{second_field}{Resources.SEP}" \
              f"{password_hash}{Resources.SEP}" \
              f"{rsa_pk}{Resources.SEP}" \
              f"{elgamal_pk}{Resources.SEP}" \
              f"{prekey_pk}{Resources.SEP}"
    send_to_server(message, sign=(message_type != "register"))
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

    return User(username, Resources.get_hash(username + password), rsa_pk, elgamal_pk, prekey_pk, rsa_pr, elgamal_pr,
                prekey_pr)


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
    load_db(username, Resources.get_hash(username + password))
    message = f"login{Resources.SEP}" \
              f"{username}"
    send_to_server(message, False)
    response = receive_from_server().split(Resources.SEP)

    if response[0] == "200":
        salt = response[2]
        password_hash = Resources.get_hash(username + password)
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
    return response[2]


def show_users_list():
    print(retrieve_usernames_from_server())


def logout():
    global client_user, users, chats

    message = "logout"
    send_to_server(message, True)
    save_to_db()

    response = receive_from_server().split(Resources.SEP)
    print(response[2])

    client_user = None
    users = []
    chats = {}
    return


def x3dh_key_exchange(target_user: User, seq=0) -> bool:
    print("sending key...")

    ek_pr, ek_pk = ElGamal.gen_key()

    DH1 = ElGamal.DH_key(target_user.prekey_pk, client_user.elgamal_pr)
    DH2 = ElGamal.DH_key(target_user.elgamal_pk, ek_pr)
    DH3 = ElGamal.DH_key(target_user.prekey_pk, ek_pr)

    SK = AES.generate_symmetric_key(str(DH1) + str(DH2) + str(DH3))

    chat = chats[target_user.username]
    chat.root_key = SK
    chat.DH_key = ElGamal.DH_key(target_user.prekey_pk, client_user.prekey_pr)
    chat.our_pr = client_user.prekey_pr
    chat.their_pk = target_user.prekey_pk
    chat.their_rsa_pk = target_user.rsa_pk

    new_root_key, message_key = chat.KDF(chat.DH_key, chat.root_key)
    chat.root_key = new_root_key
    chat.message_key = message_key

    initial_message = str(client_user.elgamal_pk) \
                      + Resources.SEP + str(target_user.prekey_pk) \
                      + Resources.SEP + str(ek_pk) \
                      + Resources.SEP + client_user.rsa_pk \
                      + Resources.SEP + str(client_user.prekey_pk)

    print(initial_message)

    message_obj = Message(message_type="x3dh",
                          source_username=client_user.username,
                          target_username=target_user.username,
                          seq=seq,
                          signature=RSA.sign(str(seq) + initial_message, RSA.pem_to_private_key(client_user.rsa_pr)),
                          text=initial_message)

    chats[target_user.username].append_message(message_obj)

    request = str(message_obj)
    send_to_server(request, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3 - 1)
    return response[0] == "200"


def x3dh_extract_key(text: str):
    print("receiving key...")

    A_elgamal_pk, our_prekey_pk, A_ek_pk, their_rsa_pk, their_prekey_pk = text.split(Resources.SEP)
    A_elgamal_pk = int(A_elgamal_pk)
    our_prekey_pk = int(our_prekey_pk)
    A_ek_pk = int(A_ek_pk)
    their_prekey_pk = int(their_prekey_pk)

    DH1 = ElGamal.DH_key(A_elgamal_pk, client_user.prekey_pr)
    DH2 = ElGamal.DH_key(A_ek_pk, client_user.elgamal_pr)
    DH3 = ElGamal.DH_key(A_ek_pk, client_user.prekey_pr)

    SK = AES.generate_symmetric_key(str(DH1) + str(DH2) + str(DH3))
    return SK, their_prekey_pk, their_rsa_pk


def retrieve_keys(username: str):
    global users

    message = f"retrieve keys{Resources.SEP}" \
              f"{username}"
    send_to_server(message, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3 - 1)

    if response[0] == "200":
        rsa_pk, elgamal_pk, prekey_pk = response[2].split(Resources.SEP)
        users = [user for user in users if user.username != username]
        user = User(username, "", rsa_pk, int(elgamal_pk), int(prekey_pk))
        users.append(user)
        return True
    else:
        print(response[2])
        return False


def send_message(chat: Chat, message_type, text, target_group=""):
    print(f"sending \"{text}\" to {chat.username}...")
    fetch_messages()

    if chat.messages[-1].source_username != client_user.username:
        private_key, public_key = ElGamal.gen_key()

        if send_message_to_server(chat, "dr_pk", str(public_key)):
            chat.our_pr = private_key
            chat.DH_key = ElGamal.DH_key(chat.their_pk, private_key)
            chat.root_key, chat.message_key = chat.KDF(chat.DH_key, chat.root_key)

    return send_message_to_server(chat, message_type, text, target_group)


def send_group_message(group: Group, message_type, text):
    print(f"sending \"{text}\" to {group.group_name}...")
    fetch_messages()

    message_obj = Message(message_type="group_text",
                          source_username=client_user.username,
                          target_username=client_user.username,
                          seq=0,
                          signature=RSA.sign(str(0) + text, RSA.pem_to_private_key(client_user.rsa_pr)),
                          text=text,
                          target_group=group.group_name)

    # save our own message to chat of group
    group.chat.append_message(message_obj)

    # send the message to other members of group
    for username in group.usernames:
        if username != client_user.username:
            open_chat(username)
            send_message(chats[username], message_type, text, group.group_name)


def send_message_to_server(chat, message_type, text, target_group=""):
    new_message_key, the_ultimate_key = chat.KDF(chat.DH_key, chat.message_key)

    message_obj = Message(message_type=message_type,
                          source_username=client_user.username,
                          target_username=chat.username,
                          seq=chat.seq,
                          signature=RSA.sign(str(chat.seq) + text, RSA.pem_to_private_key(client_user.rsa_pr)),
                          text=text,
                          target_group=target_group)

    encrypted_message_obj = copy.deepcopy(message_obj)
    encrypted_message_obj.text = AES.encrypt(message_obj.text, the_ultimate_key)
    request = str(encrypted_message_obj)
    send_to_server(request, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3 - 1)
    if response[0] == "200":
        chats[chat.username].append_message(message_obj)
        chat.message_key = new_message_key
        return True
    else:
        print(response[2])
        return False


def get_user_by_chat(chat: Chat):
    for user in users:
        if user.username == chat.username:
            return user


def receive_message(chat: Chat, message_obj: Message):
    # TODO: handle out of order message
    new_message_key, the_ultimate_key = chat.KDF(chat.DH_key, chat.message_key)
    chat.message_key = new_message_key

    # decrypt the message text
    message_obj.text = AES.decrypt(message_obj.text, the_ultimate_key)

    # check the message sign
    user = get_user_by_chat(chat)
    try:
        RSA.verify_signature(str(message_obj.seq) + message_obj.text, message_obj.signature,
                             RSA.pem_to_public_key(chat.their_rsa_pk))
        message_obj.source_rsa_pk = chat.their_rsa_pk
    except InvalidSignature:
        return

    # update the keys for "dr_pk" control message
    if chat.messages[-1].source_username != message_obj.source_username:
        chat.their_pk = int(message_obj.text)
        chat.DH_key = ElGamal.DH_key(chat.their_pk, chat.our_pr)
        chat.root_key, chat.message_key = chat.KDF(chat.DH_key, chat.root_key)

    chat.append_message(message_obj)
    return message_obj


def fetch_messages():
    request = f"fetch"
    send_to_server(request, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3 - 1)

    # send ACK to server to delete fetched messages
    send_to_server("ack", sign=True)

    new_messages = json.loads(response[2])
    new_messages_lists = [message.split(Resources.SEP) for message in new_messages]
    new_messages_lists.sort(key=lambda x: x[3])

    for message in new_messages:
        message_type, source_username, target_username, target_group, seq, signature, text = message. \
            split(Resources.SEP, maxsplit=7 - 1)
        message_obj = Message(message_type=message_type,
                              source_username=source_username,
                              target_username=target_username,
                              target_group=target_group,
                              seq=seq,
                              signature=signature,
                              text=text)

        if message_type not in ["add", "join", "remove"]:
            retrieve_keys(source_username)

        if message_type == "x3dh":
            SK, their_prekey_pk, their_rsa_pk = x3dh_extract_key(text)

            if source_username not in chats:
                chats[source_username] = Chat(source_username)

            chat = chats[source_username]
            chat.append_message(message_obj)

            chat.root_key = SK
            chat.DH_key = ElGamal.DH_key(their_prekey_pk, client_user.prekey_pr)
            chat.our_pr = client_user.prekey_pr
            chat.their_pk = their_prekey_pk
            chat.their_rsa_pk = their_rsa_pk

            message_obj.source_rsa_pk = chat.their_rsa_pk

            new_root_key, message_key = chat.KDF(chat.DH_key, chat.root_key)
            chat.root_key = new_root_key
            chat.message_key = message_key

        elif message_type == "dr_pk":
            chat = chats[source_username]
            receive_message(chat, message_obj)

        elif message_type == "text":
            chat = chats[source_username]
            receive_message(chat, message_obj)

        elif message_type == "group_text":
            chat = chats[source_username]
            message_obj = receive_message(chat, message_obj)
            group = groups[message_obj.target_group]
            group.chat.append_message(message_obj)

        elif message_type == "add":
            try:
                RSA.verify_signature(str(seq) + text, message_obj.signature, server_public_key)
            except InvalidSignature:
                continue
            new_member_username, group_name = text.split(Resources.SEP)
            groups[group_name].usernames.append(new_member_username)
            groups[group_name].chat.append_message(message_obj)

        elif message_type == "join":
            try:
                RSA.verify_signature(str(seq) + text, message_obj.signature, server_public_key)
            except InvalidSignature:
                continue
            admin_username, group_name, dumped_usernames = text.split(Resources.SEP)
            if group_name not in groups:
                group = Group(admin_username, group_name)
                groups[group.group_name] = group
            groups[group_name].usernames = json.loads(dumped_usernames)
            groups[group_name].chat.append_message(message_obj)

        elif message_type == "remove":
            try:
                RSA.verify_signature(str(seq) + text, message_obj.signature, server_public_key)
            except InvalidSignature:
                continue
            removed_member_username, group_name = text.split(Resources.SEP)
            groups[group_name].usernames.remove(removed_member_username)
            groups[group_name].chat.append_message(message_obj)


def print_chat(chat: Chat):
    for message in chat.messages:
        if message.message_type == "x3dh":
            print(f"{message.source_username} has started a secret chat.")
        elif message.message_type == "text":
            print(f"{message.source_username}:\t{message.text}")


def print_group(group: Group):
    for message in group.chat.messages:
        if message.message_type == "group_text":
            print(f"{message.source_username}:\t{message.text}")

        elif message.message_type == "add":
            admin_name = group.admin_username
            admin_name = "you" if admin_name == client_user.username else admin_name
            print(f"{admin_name} added {message.text.split(Resources.SEP)[0]} to this group.")

        elif message.message_type == "join":
            print(f"{group.admin_username} added you to this group.")

        elif message.message_type == "remove":
            admin_name = group.admin_username if group.admin_username != client_user.username else "you"
            member_name = message.text.split(Resources.SEP)[0]
            member_name = "you" if member_name == client_user.username else member_name
            print(f"{admin_name} removed {member_name} from this group.")


def open_chat(username: str) -> bool:
    if client_user.username == username:
        print("You cannot send message you yourself.")
        return False

    fetch_messages()

    if username in chats:
        return True

    # Let's do the magic!
    if retrieve_keys(username):
        for user in users:
            if user.username == username:
                chats[user.username] = Chat(user.username)
                x3dh_key_exchange(user)
        return True

    return False


def verify_keys(chat: Chat):
    fetch_messages()
    print("To verify the conversation is end-to-end encrypted, compare the following hash of keys with your friend's:")
    print(Resources.get_hash(chat.message_key)[:5])


def chat_menu(chat: Chat):
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Welcome {client_user.username}.")
        print(f"Recipient: {chat.username}\n")
        print("  1: refresh\n"
              "  2: send <message>\n"
              "  3: verify keys\n"
              "  4: back")
        command = input("  > ").split()
        print()
        if len(command) == 0:
            continue
        if command[0] == "refresh":
            fetch_messages()
            print_chat(chat)
        elif command[0] == "send":
            send_message(chat, "text", ' '.join(command[1:]))
        elif command[0] == "verify":
            verify_keys(chat)
        elif command[0] == "back":
            return
        else:
            print("Wrong command!")


def create_group(group_name: str):
    request = f"create{Resources.SEP}{group_name}"
    send_to_server(request, sign=True)
    response = receive_from_server().split(Resources.SEP, maxsplit=3 - 1)
    if response[0] == "200":
        group = Group(client_user.username, group_name)
        groups[group_name] = group
        print(response[2])
        return True

    print(response[2])


def open_group(group_name: str) -> bool:
    if group_name in chats:
        print("This username belong to a user, not a group.")
        return False

    fetch_messages()

    if group_name in groups:
        return True

    else:
        print("The group does not exist")
        return False


def list_group_members(group: Group):
    fetch_messages()

    users_log = retrieve_usernames_from_server().split("\n")
    for line in users_log:
        username = line.split(" ")[1]
        if username in group.usernames:
            print(line)


def add_member_to_group(group: Group, new_member_username: str):
    fetch_messages()
    message = f"add{Resources.SEP}{group.group_name}{Resources.SEP}{new_member_username}"
    send_to_server(message, True)
    response = receive_from_server().split(Resources.SEP)

    print(response[2])


def remove_member_from_group(group: Group, member_username: str):
    fetch_messages()
    message = f"remove{Resources.SEP}{group.group_name}{Resources.SEP}{member_username}"
    send_to_server(message, True)
    response = receive_from_server().split(Resources.SEP)

    print(response[2])


def verify_group_keys(group: Group):
    fetch_messages()
    print(
        "To verify the conversation is end-to-end encrypted, compare the following hashes of keys with your friends':")
    for username in group.usernames:
        if username != client_user.username:
            try:
                print(username + ": " + Resources.get_hash(chats[username].message_key)[:5])
            except KeyError:
                print(username + ": " + "none")


def group_menu(group: Group):
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Welcome {client_user.username}.")
        print(f"Group: {group.group_name}\n")
        print("  1: refresh\n"
              "  2: send <message>\n"
              "  3: verify keys\n"
              "  4: add <username>\n"
              "  5: remove <username>\n"
              "  5: list members\n"
              "  6: back")
        command = input("  > ").split()
        print()
        if len(command) == 0:
            continue
        if command[0] == "refresh":
            fetch_messages()
            print_group(group)
        elif command[0] == "send":
            send_group_message(group, "group_text", ' '.join(command[1:]))
        elif command[0] == "verify":
            # TODO
            verify_group_keys(group)
        elif command[0] == "add":
            add_member_to_group(group, command[1])
        elif command[0] == "remove":
            remove_member_from_group(group, command[1])
        elif command[0] == "list":
            list_group_members(group)
        elif command[0] == "back":
            return
        else:
            print("Wrong command!")


def renew_keys(old_password, new_password):
    # fetch messages received from other users based on our old keys
    fetch_messages()

    if Resources.get_hash(client_user.username + old_password) != client_user.password_hash:
        print("Wrong password.")
        return
    old_password_hash = Resources.get_hash(client_user.username + old_password)
    if initialize_user("renew", client_user.username, new_password, old_password_hash):
        for target_user in users:
            x3dh_key_exchange(target_user)


def user_menu():
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Welcome {client_user.username}.\n")
        print("  1: show users list\n"
              "  2: open chat <username>\n"
              "  3: create group <group_name>\n"
              "  4: open group <group_name>\n"
              "  5: renew keys <old password> <new password>\n"
              "  6: logout")
        command = input("  > ").split()
        print()
        if len(command) == 0:
            continue
        if command[0] == "show":
            show_users_list()
        elif command[0] == "open" and command[1] == "chat":
            if open_chat(command[2]):
                chat_menu(chats[command[2]])
        elif command[0] == "create":
            if create_group(command[2]):
                group_menu(groups[command[2]])
        elif command[0] == "open" and command[1] == "group":
            if open_group(command[2]):
                group_menu(groups[command[2]])
        elif command[0] == "renew":
            old_password = getpass("Old password: ")
            new_password = getpass("New password: ")
            renew_keys(old_password, new_password)
        elif command[0] == "logout":
            logout()
            return
        else:
            print("Wrong command!")


def main_menu():
    while True:
        input("Press Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')

        print("  1: register <username>\n"
              "  2: login <username>")
        command = input("  > ").split()
        print()
        if len(command) == 0:
            continue
        if command[0] == "register" and len(command) == 2:
            password = getpass()
            if register_new_user(command[1], password):
                user_menu()
        elif command[0] == "login" and len(command) == 2:
            password = getpass()
            if login_user(command[1], password):
                user_menu()
        else:
            print("Wrong command!")


if __name__ == "__main__":
    https_socket = establish_HTTPS_connection()
    try:
        main_menu()
    finally:
        if client_user is not None:
            print("Something bad happened. Logging out...")
            save_to_db()
            logout()
        https_socket.close()
