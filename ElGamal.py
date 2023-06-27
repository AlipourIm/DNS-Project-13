import random

import Resources

alpha = 7
q = 10 ** 50


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


def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


def gen_key(username=None, password=None, keyname="elgamal"):  # TODO: use cryptography library for random key generation
    private_key = random.randint(10 ** 20, q)
    while gcd(q, private_key) != 1:
        private_key = random.randint(10 ** 20, q)
    public_key = power(alpha, private_key, q)

    if username is not None:
        Resources.save_keys(username, password, keyname, str(private_key), str(public_key))

    return private_key, public_key


def encryption(msg, public_key):
    ct = []
    k, _ = gen_key()
    s = power(public_key, k, q)
    p = power(alpha, k, q)
    for i in range(0, len(msg)):
        ct.append(msg[i])
    for i in range(0, len(ct)):
        ct[i] = s * ord(ct[i])
    return ct, p


def decryption(ct, p, private_key):
    pt = []
    h = power(p, private_key, q)
    for i in range(0, len(ct)):
        pt.append(chr(int(ct[i] / h)))
    result = ''.join(pt)
    return result


def validate_keys(pr, pk):
    msg = "Hello world!"
    c1, c2 = encryption(msg, pk)
    dec_msg = decryption(c1, c2, pr)
    if msg != dec_msg:
        raise Resources.InvalidKeysException
    return


def DH_key(public_key: int, private_key: int) -> int:
    return power(public_key, private_key, q)


def test():
    msg = input("Enter message: ")
    private_key, public_key = gen_key("ali", "1234")
    print("alpha used=", alpha)
    c1, c2 = encryption(msg, public_key)
    print("Original Message  =", msg)
    print("Encrypted Message =", c1)
    pt = decryption(c1, c2, private_key)
    d_msg = ''.join(pt)
    print("Decrypted Message =", d_msg)


def test2():
    pr1, pk1 = gen_key()
    pr2, pk2 = gen_key()
    print(DH_key(pk1, pr2))
    print(DH_key(pk2, pr1))

    pk1 = 71293181205877243162061948817390834627418775844007
    pr2 = 40241777937871183506636962675501585388421733428689
    pk2 = 43663677688158500221844850058921947500010626409607
    pr1 = 71293181205877243162061948817390834627418775844007
    return

