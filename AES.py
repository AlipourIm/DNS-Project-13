import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import Resources


default_iv = "0000000000000000"


def generate_symmetric_key(raw_key: str):
    key = Resources.get_hash(raw_key)[:32]
    return key


def encrypt(message: str, key: str, iv=default_iv):
    tmp_message = message
    extra = len(tmp_message) % 16
    if extra > 0:
        tmp_message = tmp_message + (' ' * (16 - extra))
    cipher = Cipher(algorithms.AES(key.encode("ASCII")), modes.CBC(iv.encode("ASCII")))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(tmp_message.encode("ASCII")) + encryptor.finalize()
    return base64.b64encode(cipher_text).decode("ASCII")


def decrypt(cipher_text: str, key: str, iv=default_iv):
    cipher = Cipher(algorithms.AES(key.encode("ASCII")), modes.CBC(iv.encode("ASCII")))
    decipher = cipher.decryptor()
    plain = decipher.update(base64.b64decode(cipher_text.encode("ASCII"))) + decipher.finalize()
    return plain.decode("ASCII").rstrip(" ")


def test():
    message = "1234567812345678sadf         "
    iv = "0000000000000000"
    print(iv)
    key = generate_symmetric_key("1234")
    cipher_text = encrypt(message, key, iv)
    print(cipher_text)
    plain_text = decrypt(cipher_text, key, iv)
    print(plain_text)
