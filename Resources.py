import hashlib
import os
import sys

import AES

SEP = "\r\n\r\n"
BUFFER_SIZE = 10**6


def save_keys(username: str, password: str, method: str, private_key: str, public_key: str):
    if not os.path.isdir("./user"):
        os.mkdir("./user")

    if not os.path.isdir(f"./user/{username}"):
        os.mkdir(f"./user/{username}")

    with open(f"./user/{username}/{method}_private.key", 'wb') as content_file:
        os.chmod(f"./user/{username}/{method}_private.key", 0o600)
        aes_key = AES.generate_symmetric_key(password)
        private_key_encrypted = AES.encrypt(private_key, aes_key, AES.default_iv)
        content_file.write(private_key_encrypted.encode("ASCII"))

    with open(f"./user/{username}/{method}_public.key", 'wb') as content_file:
        content_file.write(public_key.encode("ASCII"))

    return


def load_keys(username, password, privates):
    with open(f"./user/{username}/rsa_public.key", "rb") as key_file:
        rsa_pk = key_file.read().decode("ASCII")

    with open(f"./user/{username}/elgamal_public.key", "rb") as key_file:
        elgamal_pk = int(key_file.read().decode("ASCII"))

    if privates:
        try:
            aes_key = AES.generate_symmetric_key(password)
            with open(f"./user/{username}/rsa_private.key", "rb") as key_file:
                encrypted_rsa_pr = key_file.read().decode("ASCII")
                rsa_pr = AES.decrypt(encrypted_rsa_pr, aes_key)

            with open(f"./user/{username}/elgamal_private.key", "rb") as key_file:
                encrypted_elgamal_pr = key_file.read().decode("ASCII")
                elgamal_pr = int(AES.decrypt(encrypted_elgamal_pr, aes_key))
        except UnicodeDecodeError:
            raise WrongPasswordException

        return rsa_pr, rsa_pk, elgamal_pr, elgamal_pk

    return rsa_pk, elgamal_pk


def get_hash(s: str):
    return hashlib.sha256(s.encode("ASCII")).hexdigest()


class NotFreshException(Exception):
    pass


class InvalidKeysException(Exception):
    pass


class WrongPasswordException(Exception):
    pass
