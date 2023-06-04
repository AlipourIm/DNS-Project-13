from os import chmod
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# with open("./tmp/private.key", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend=default_backend()
#     )
#
# with open("./tmp/public.key", "rb") as key_file:
#     public_key = serialization.load_pem_public_key(
#         key_file.read(),
#         backend=default_backend()
#     )
#
# print(public_key.public_numbers())
# print(private_key.private_numbers().public_numbers)
# print(private_key.private_numbers().d)
#
# d = private_key.private_numbers().d
# p = private_key.private_numbers().p
# q = private_key.private_numbers().q
# n = public_key.public_numbers().n
# e = public_key.public_numbers().e
#
# print(d * e % ((p - 1) * (q - 1)) == 1)
#
# message = b'encrypt me!'
#
#
# print(original_message)

################################################################################
################################################################################
################################################################################
################################################################################
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


with open("./tmp/private.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open("./tmp/public.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

with open("./tmp/private2.key", "rb") as key_file:
    private_key2 = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open("./tmp/public2.key", "rb") as key_file:
    public_key2 = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

d = private_key.private_numbers().d
p = private_key.private_numbers().p
q = private_key.private_numbers().q
n = public_key.public_numbers().n
e = public_key.public_numbers().e

d2 = private_key2.private_numbers().d
p2 = private_key2.private_numbers().p
q2 = private_key2.private_numbers().q
n2 = public_key2.public_numbers().n
e2 = public_key2.public_numbers().e


def custom_pow(base, exp, mod):
    arr = []
    while exp:
        arr.append(exp % 2)
        exp //= 2
    res = 1
    for i in reversed(arr):
        res = (base if i else 1) * res ** 2
        res %= mod
    return res


# print(custom_pow(5, 41, 65))
# print(custom_pow(5, 29, 65))
print(custom_pow(e2, d, n) == custom_pow(e, d2, n))
print(custom_pow(2, 11, 1000))
print(custom_pow(5, 29, 299) == custom_pow(5, 653, 299))

# key = (d**e2)
# iv = os.urandom(16)
# cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
# encryptor = cipher.encryptor()
# ct = encryptor.update(b"a secret message") + encryptor.finalize()
# decryptor = cipher.decryptor()
# decryptor.update(ct) + decryptor.finalize()
#
# message = b'encrypt me!'
# print((message ** e) % n)
