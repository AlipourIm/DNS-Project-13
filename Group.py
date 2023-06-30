from typing import List

from Chat import Chat


class Group:

    def __init__(self, admin_username, group_name):
        self.admin_username = admin_username
        self.group_name = group_name
        self.chat = Chat(group_name)
        self.usernames: List[str] = [admin_username]
