import hashlib as hash
import secrets
import string
import time

import bcrypt
import matplotlib.pyplot as plt
import scrypt
import binascii
import mhashlib
import uuid
from passlib.hash import bcrypt as blowfish


class blowfish_hash:
    name = "blowfish"

    def __init__(self):
        pass

    def update(self, str):
        return blowfish.using(rounds=14, ident="2y").hash(str)


class haval_hash:
    name = "HAVAL"

    def __init__(self):
        pass

    def update(self, str):
        return mhashlib.haval().update(str)


class scrypt_hash:
    name = "scrypt"

    def __init__(self):
        pass

    def update(self, str):
        return scrypt.hash(str, "")


class bcrypt_hash:
    name = "bcrypt"

    def __init__(self):
        pass

    def update(self, str):
        return bcrypt.hashpw(str, bcrypt.gensalt())


class ntlm_hash:
    name = "NTLM"

    def __init__(self):
        pass

    def update(self, str):
        hash_str = hash.new('md4', str.encode('utf-16le')).digest()
        return binascii.hexlify(hash_str)


def expr(hasher, str):
    start = time.time()
    if hasher.name != "NTLM":
        hasher.update(str.encode('utf-8'))
    else:
        hasher.update(str)
    return time.time() - start


def generate_string(length, without_salt=True):
    str = ''.join(secrets.choice(string.printable) for i in range(length))
    if without_salt:
        return str
    else:
        return str + uuid.uuid4().hex


fast_hashers = [
    hash.md5(),
    hash.sha256(),
    hash.sha512(),
    hash.sha1(),
    haval_hash(),
    ntlm_hash(),
]
slow_hashers = [
    scrypt_hash(),
    bcrypt_hash(),
    blowfish_hash()
]

for length in [8, 20, 60, 5000]:
    fig, ax = plt.subplots()
    for hasher in fast_hashers:
        if hasher.name != "blowfish" or length != 5000:
            ax.barh(hasher.name, expr(hasher, generate_string(length)))
            ax.barh(hasher.name + " with salt", expr(hasher, generate_string(length, False)))
    plt.title('Hashing string length:' + str(length))
    plt.show()

for length in [8, 20, 60, 5000]:
    fig, ax = plt.subplots()
    for hasher in slow_hashers:
        if hasher.name != "blowfish" or length != 5000:
            ax.barh(hasher.name, expr(hasher, generate_string(length)))
            ax.barh(hasher.name + " with salt", expr(hasher, generate_string(length, False)))
    plt.title('Hashing string length:' + str(length))
    plt.show()
