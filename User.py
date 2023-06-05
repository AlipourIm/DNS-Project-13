import hashlib

import Resources


class User:
    def __init__(self, username, password_hash, rsa_pk, elgamal_pk):
        self.elgamal_pk = elgamal_pk
        self.rsa_pk = rsa_pk
        self.password_hash = password_hash
        self.username = username
        self.is_online = True

    def set_online(self):
        self.is_online = True

    def set_offline(self):
        self.is_online = False

    def check_password(self, salt: str, otp: str):
        return Resources.get_hash(salt + self.password_hash) == otp
