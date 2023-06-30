import random
import socket
import datetime

import AES
import RSA
import Resources


class SecureSocket(socket.socket):
    seq: int = 0
    aes_key: str = ""
    raw_socket: socket.socket

    def send(self, __data: bytes, __flags: int = ...) -> int:
        if self.aes_key == "":
            return self.raw_socket.send(__data)
        else:
            data = (str(self.seq) + Resources.SEP + str(datetime.datetime.now()) + Resources.SEP).encode('ASCII') \
                    + __data
            self.seq += 1
            return self.raw_socket.send(AES.encrypt_bytes(data, self.aes_key))

    def recv(self, __bufsize: int, __flags: int = ...) -> bytes:
        if self.aes_key == "":
            return self.raw_socket.recv(__bufsize)
        else:
            raw_data = self.raw_socket.recv(__bufsize)

            if len(raw_data) == 0:
                return raw_data

            arr = AES.decrypt_bytes(raw_data, self.aes_key).split(Resources.SEP.encode("ASCII"), maxsplit=3 - 1)
            seq = int(arr[0])
            timestamp = arr[1].decode("ASCII")
            try:
                assert seq == self.seq
                Resources.verify_timestamp(timestamp)
                self.seq += 1
                return arr[2]
            except (AssertionError, Resources.NotFreshException):
                print("SecureSocket: Invalid packet received.")
                print(seq, self.seq)
                return self.recv(__bufsize)

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
