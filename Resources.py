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


def get_hash(s: str):
    return hashlib.sha256(s.encode("ASCII")).hexdigest()
