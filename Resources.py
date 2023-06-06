import hashlib
import os


SEP = "\r\n\r\n"
BUFFER_SIZE = 10**6


def save_keys(username: str, method: str, private_key: str, public_key: str):
    if not os.path.isdir("./user"):
        os.mkdir("./user")

    if not os.path.isdir(f"./user/{username}"):
        os.mkdir(f"./user/{username}")

    with open(f"./user/{username}/{method}_private.key", 'wb') as content_file:
        os.chmod(f"./user/{username}/{method}_private.key", 0o600)
        content_file.write(private_key.encode("ASCII"))

    with open(f"./user/{username}/{method}_public.key", 'wb') as content_file:
        content_file.write(public_key.encode("ASCII"))


def load_keys(username, password, privates):
    with open("./tmp/public.key", "rb") as key_file:
        rsa_pk = key_file.read().decode("ASCII")

    with open(f"./user/{username}/elgamal_public.key", "rb") as key_file:
        elgamal_pk = int(key_file.read().decode("ASCII"))

    if privates:
        with open(f"./user/{username}/rsa_private.key", "rb") as key_file:
            rsa_pr = key_file.read().decode("ASCII")

        with open(f"./user/{username}/elgamal_private.key", "rb") as key_file:
            elgamal_pr = int(key_file.read().decode("ASCII"))

        return rsa_pr, rsa_pk, elgamal_pr, elgamal_pk

    return rsa_pk, elgamal_pk


def get_hash(s: str):
    return hashlib.sha256(s.encode("ASCII")).hexdigest()


class NotFreshException(Exception):
    pass
