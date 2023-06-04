import random


def power(base, exp, mod):
    arr = []
    while exp:
        arr.append(exp % 2)
        exp //= 2
    res = 1
    for i in reversed(arr):
        res = (base if i else 1) * res ** 2
        res %= mod
    return res


class ElGamal:
    alpha = 7
    q = 10 ** 50

    def gcd(self, a, b):
        if a < b:
            return self.gcd(b, a)
        elif a % b == 0:
            return b
        else:
            return self.gcd(b, a % b)

    def gen_key(self):  # TODO: use cryptography library for random key generation
        private_key = random.randint(10 ** 20, self.q)
        while self.gcd(self.q, private_key) != 1:
            private_key = random.randint(10 ** 20, self.q)
        public_key = power(self.alpha, private_key, self.q)
        return private_key, public_key

    def encryption(self, msg, public_key):
        ct = []
        k, _ = self.gen_key()
        s = power(public_key, k, self.q)
        p = power(self.alpha, k, self.q)
        for i in range(0, len(msg)):
            ct.append(msg[i])
        print("g^k used= ", p)
        print("g^ak used= ", s)
        for i in range(0, len(ct)):
            ct[i] = s * ord(ct[i])
        return ct, p

    def decryption(self, ct, p, private_key):
        pt = []
        h = power(p, private_key, self.q)
        for i in range(0, len(ct)):
            pt.append(chr(int(ct[i] / h)))
        return pt

    def test(self):
        msg = input("Enter message: ")
        private_key, public_key = self.gen_key()
        print("alpha used=", self.alpha)
        c1, c2 = self.encryption(msg, public_key)
        print("Original Message  =", msg)
        print("Encrypted Message =", c1)
        pt = self.decryption(c1, c2, private_key)
        d_msg = ''.join(pt)
        print("Decrypted Message =", d_msg)
