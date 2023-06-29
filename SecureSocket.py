import random
import socket

import AES
import RSA
import Resources


class SecureSocket(socket.socket):
    aes_key: str = ""
    raw_socket: socket.socket

    def send(self, __data: bytes, __flags: int = ...) -> int:
        if self.aes_key == "":
            return self.raw_socket.send(__data)
        else:
            return self.raw_socket.send(AES.encrypt_bytes(__data, self.aes_key))

    def recv(self, __bufsize: int, __flags: int = ...) -> bytes:
        if self.aes_key == "":
            return self.raw_socket.recv(__bufsize)
        else:
            return AES.decrypt_bytes(self.raw_socket.recv(__bufsize), self.aes_key)

    def establish_client(self, public_key):
        raw_key = str(random.randint(0, 10**6))
        key = AES.generate_symmetric_key(raw_key)
        self.send(RSA.encrypt(key, public_key))
        self.aes_key = key

    def establish_server(self, private_key):
        encrypted_key = self.recv(Resources.BUFFER_SIZE)
        self.aes_key = RSA.decrypt(encrypted_key, private_key)


def wrap_socket(raw_socket) -> SecureSocket:
    secure_socket = SecureSocket()
    secure_socket.raw_socket = raw_socket
    return secure_socket
