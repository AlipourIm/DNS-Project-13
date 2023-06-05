class User:
    def __init__(self, username, password, rsa_pk, elgamal_pk):
        self.elgamal_pk = elgamal_pk
        self.rsa_pk = rsa_pk
        self.password = password
        self.username = username
        self.is_online = True

    def set_online(self):
        self.is_online = True

    def set_offline(self):
        self.is_online = False
