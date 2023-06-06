import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend, default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import Resources


def gen_key(username):
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PublicFormat.PKCS1
    )

    Resources.save_keys(username, "rsa", private_key.decode("ASCII"), public_key.decode("ASCII"))

    return private_key.decode("ASCII"), public_key.decode("ASCII")


def encryption(message, public_key):
    encrypted = public_key.encrypt(
        message.encode("ASCII"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted


def decryption(encrypted_message, private_key):
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode("ASCII")

    return original_message


def sign(message, private_key):
    signature = private_key.sign(
        message.encode("ASCII"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature = base64.b64encode(signature)
    signature = signature.decode("ASCII")

    return signature


def verify_signature(message, signature, public_key):
    signature = signature.encode("ASCII")
    signature = base64.b64decode(signature)

    return public_key.verify(
        signature,
        message.encode("ASCII"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def pem_to_private_key(private_key):
    return serialization.load_pem_private_key(
        private_key.encode("ASCII"),
        password=None,
        backend=default_backend()
    )


def pem_to_public_key(public_key):
    return serialization.load_pem_public_key(
        public_key.encode("ASCII"),
        backend=default_backend()
    )


def test():
    pr, pk = gen_key("ali")
    msg = "Hello world!"
    enc_msg = encryption(msg, pem_to_public_key(pk.decode("ASCII")))
    print(enc_msg)

    dec_msg = decryption(enc_msg, pem_to_private_key(pr.decode("ASCII")))
    print(dec_msg)

    sig = sign(msg, pem_to_private_key(pr.decode("ASCII")))
    print(sig)

    try:
        verify_signature(msg, sig, pem_to_public_key(pk.decode("ASCII")))
        print("signatures match")
    except InvalidSignature:
        print("signatures do not match")
