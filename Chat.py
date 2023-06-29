from typing import List

import Resources
from Message import Message


class Chat:

    def __init__(self, username):
        self.seq = 0  # Next expected message
        self.username = username
        self.messages: List[Message] = []
        self.root_key: str = ""
        self.message_key: str = ""
        self.DH_key: int = 0
        self.our_pr: int = 0
        self.their_pk: int = 0

    def append_message(self, message: Message):
        self.messages.append(message)
        if message.seq == self.seq:
            self.seq += 1

    def report_chat_keys(self):
        print(f"chat.DH_key:      {self.DH_key}\n"
              f"chat.root_key:    {self.root_key}\n"
              f"chat.message_key: {self.message_key}\n\n")

    def KDF(self, constant, chain_key):
        print("before KDF...")
        self.report_chat_keys()
        the_hash = Resources.get_hash(str(constant) + str(chain_key))[:64]
        new_chain_key = the_hash[0:32]
        message_key = the_hash[32:64]
        print("after KDF...")
        self.report_chat_keys()
        return new_chain_key, message_key
