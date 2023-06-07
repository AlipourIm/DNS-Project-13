import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend, default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import Resources


def gen_key(username, password):
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

    Resources.save_keys(username, password, "rsa", private_key.decode("ASCII"), public_key.decode("ASCII"))

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


def validate_keys(pr, pk):
    msg = "Hello world!"
    enc_msg = encryption(msg, pem_to_public_key(pk))
    dec_msg = decryption(enc_msg, pem_to_private_key(pr))
    if msg != dec_msg:
        raise Resources.InvalidKeysException
    return


def test():
    pr, pk = gen_key("ali", "1234")
    msg = "Hello world!"
    enc_msg = encryption(msg, pem_to_public_key(pk))
    print(enc_msg)

    dec_msg = decryption(enc_msg, pem_to_private_key(pr))
    print(dec_msg)

    sig = sign(msg, pem_to_private_key(pr))
    print(sig)

    try:
        verify_signature(msg, sig, pem_to_public_key(pk))
        print("signatures match")
    except InvalidSignature:
        print("signatures do not match")


def test2():
    rsa_pr = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh1pPlSRcuzVKf
mEte6GiPDgKpeSF4LROXgbQQ+8sjfpZ3WTbjKZ7gzRX4B88dVJAK+uWDXE/3nlY3
Wy62FbPqJkpR8igRCJl7H6jZPvxTfqrXjbkUTcHLm8a2/MFIru22GXCs5UPLNnPv
NVmPqqbS2yeN2o6fz8syBpvI0EDvJpybPGGqU7KbRNqQagLID9uCwq+Bdgz1u3eC
bUWgR6Zmv9DDRcaICYqssIFIIw7fh9lfOxPJ8VfPMZdO/C176scUCOMc1fV+ypCX
9GtPZwBgSrcLLzy0cqytCZwkMNBAnKPfCy9dvhIqNclA8A5ldwIsGtCv7OW3ywPm
oqQn/1x/AgMBAAECggEAEAKMPYbu88xufQ3o2fOT5gBSQ/1oWAKqDuWNBF81SXDh
7dgPQg9jSgB//DNhhWzHQWAEAUn8CUvaRNZb+2CSfpj0T9bg7EQ1zTqzV6NVc/3Y
0qsjYcMZZ/vFHJfSg/qSs4QeLsOaCL/1fBHGJZ8tcGlE5pOF5OJwPz2ksZnB4LIz
708Jr28DbsmseHwg1+gTggKI1tlRMwNBF4HOFjnX2mU8ZsB6F1Zgr3p0oggeMsG5
2XTAtyHACQbSchNxq0+uYiO/VK9XtP0rQUQLNLHB9Bs8mtbkJxqyyL3PdBxE0WS2
Oy743UyUTeiC6KD21OvFJWh3U+fS6X7QA0WqU1pi4QKBgQD44c2/fQGdURKm6TXH
pyHU2eOSK8Yun0ry0TgwSMlrouU6YZX9LqIPtkmuHqcq46EWfjZJX4sHQuFuZm+V
61Gij1tIWV+n0vw6t0GkrImq+lZtSwPXd76Zo94fZ+3SWyw3wfdyuFXpu3M9Uwkm
lNUM24j5II2+hKqcGx33WCff9wKBgQDoTA7QGv0RxjkTPrMAKyDAWIgeQBQmZEzO
mJUzwYL2wc9pwBTn4rDDe8s2iaYyEbnD6naCke/IZ8n2YuE90YsNt10vn3/CW2uU
q0nykPVupF+WAahPatTPgz3FJIdEHR4C/IBIlo9pbNdwpYGMkuLdHZFAHx9NCWAE
8Ff0f1rVuQKBgDEbRKBqxt3GeFqsmyropDk+QLO/pVvfnEcq1t5YDj4JpxcM2C5b
fCiDfCg57hv9S/SHNKjnjCQDoz1IQu4evz3G8WjmEYSokZH4RKB8VrGAsXrhGUHz
Y40nExW5SOh/isr5n5xoGLOEg+lur9iH9z2RN4aIUM9tl8gzZYc/QqbjAoGBALbg
OcEnnhfCH+jAsZbuXQhQKkj2VWasC7ORd9SZAYtVpP4x08OCOXqMGL1EvGwqfD56
dPXyAf2Zh+vKiFxsfLY9psT5IlFWO2l9N+gYqr+B9CZaA7ER/5umTJjJWxwKeDgN
pMiAj0KGB02NXmHWuXct8c2zMqcpPEhnFjdLk60xAoGAZYYTKuQUyjnUYcMsa5WN
8+8FrGU+kE1fLIuItfGINmVwaut2HMX+60vEuuxeVGeLtNE1ktAYtQGp2ID1aFs4
Et2w1MAajr2bWkKACgbULMUAkdgBnFi87VMCi2EPTBGeI0m7GUi0fIHntwwHHicp
sgR1RVkb4Web8B5T/+qwNho=
-----END PRIVATE KEY-----
"""
    rsa_pk = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4daT5UkXLs1Sn5hLXuhojw4CqXkheC0Tl4G0EPvLI36Wd1k24yme
4M0V+AfPHVSQCvrlg1xP955WN1suthWz6iZKUfIoEQiZex+o2T78U36q1425FE3B
y5vGtvzBSK7tthlwrOVDyzZz7zVZj6qm0tsnjdqOn8/LMgabyNBA7yacmzxhqlOy
m0TakGoCyA/bgsKvgXYM9bt3gm1FoEemZr/Qw0XGiAmKrLCBSCMO34fZXzsTyfFX
zzGXTvwte+rHFAjjHNX1fsqQl/RrT2cAYEq3Cy88tHKsrQmcJDDQQJyj3wsvXb4S
KjXJQPAOZXcCLBrQr+zlt8sD5qKkJ/9cfwIDAQAB
-----END RSA PUBLIC KEY-----"""
    validate_keys(rsa_pr, rsa_pk)

    # signature = sign(msg, pem_to_private_key(rsa_pr))
    # verify_signature(msg, signature, pem_to_public_key(rsa_pk))
