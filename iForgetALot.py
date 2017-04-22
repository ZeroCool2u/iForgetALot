from __future__ import absolute_import, division, print_function

import base64
import binascii
######################################
import gc
import os
import os.path
import struct
import time
from collections import defaultdict

import six
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

db = defaultdict()
decrypted = None
backend = default_backend()
salt = bytes([42])
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class CTRFernet(object):
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "CTRFernet key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA512(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        h = HMAC(self._signing_key, hashes.SHA512(), backend=self._backend)
        h.update(data[:-64])
        try:
            h.verify(data[-64:])
        except InvalidSignature:
            raise InvalidToken

        iv = data[9:25]
        ciphertext = data[25:-64]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded


class MultiFernet(object):
    def __init__(self, fernets):
        fernets = list(fernets)
        if not fernets:
            raise ValueError(
                "MultiFernet requires at least one CTRFernet instance"
            )
        self._fernets = fernets

    def encrypt(self, msg):
        return self._fernets[0].encrypt(msg)

    def decrypt(self, msg, ttl=None):
        for f in self._fernets:
            try:
                return f.decrypt(msg, ttl)
            except InvalidToken:
                pass
        raise InvalidToken


def retrieve_key():
    with open("master_passwd", 'rb') as  mass_pass_file:
        keyfiledata = mass_pass_file.read()
        old_salt = keyfiledata[:len(salt)]
        key = keyfiledata[len(salt):]
    return key

def check_integrity():
    # check integrity of files
    # TODO finish implementation
    with open("passwd_file", 'rb') as pass_file:
        key = retrieve_key()
        encoded = base64.urlsafe_b64encode(key)
        f = CTRFernet(encoded)
        pf = pass_file.read()
        print(str(pf))
        encryptedToken = f.encrypt(pf)
        decrypted = f.decrypt(encryptedToken)
        print(decrypted)
    print("Checking file integrity.")


def register_account(file, username, password, domain):
    """Register a new account"""
    # TODO finish implementation
    print("Registering a new account.")
    db[domain] = (username, password)
    del username
    del password
    del domain
    gc.collect()
    print('Registration and cleanup complete.')


def delete_account(file, username, password, domain):
    # delete account
    # TODO finish implementation
    print("Deleting account.")


def change_account(file, username, old_password, new_password, domain):
    # change the password of an account already in the manager
    # TODO finish implementation
    print("Changing password in account.")


def get_password(file, domain):
    # get a password for an account in the manager
    # TODO finish implementation
    print("Retrieving password.")


def exit_manager(file, f):
    # exit the program
    # TODO finish implementation
    # TODO encrypt file
    if f == None:
        exit()
    else:
        with open("passwd_file", 'wb') as pass_file:
            # encrypted = f.encrypt(file)
            encrypted = f.encrypt(b"TEST")
            pass_file.write(encrypted)
    print("Exiting program. Goodbye.")


def initial_registration():
    # TODO finish implementation
    # creates master_passwd file
    with open("master_passwd", 'wb') as mass_pass_file:
        check = False
        while not check:
            inp = input("Please enter your desired master password: ")
            check = user_input_is_good(inp)
            inp = bytes(inp, 'utf-8')
            if check:
                print("Generating key")
                key = kdf.derive(inp)
                mass_pass_file.write(salt + key)
    # creates passwd_file
    with open("passwd_file", 'wb') as pass_file:
        pass



def check_master_password(master_password):
    # TODO finish implementation
    print("checking master password")
    key = retrieve_key()
    master_password = bytes(master_password, 'utf-8')
    try:
        kdf.verify(master_password, key)
        print("Password accepted")
    except:
        print("WRONG MASTER PASSWORD!")
        exit()

def user_input_is_good(inp):
    # TODO finish implementation
    if len(inp) > 80:
        print("Input too long, possible attack detected. Please try again")
        return False
    else:
        return True


def display_menu():
    print("1. Check integrity")
    print("2. Register account")
    print("3. Delete account")
    print("4. Change account")
    print("5. Get password")
    print("6. Exit")


def file_decryptor(f):
    with open("passwd_file", 'rb') as pass_file:
        pf = pass_file.read()
        return f.decrypt(pf)

if __name__ == '__main__':
    # check for passwd_file and master_passwd
    # if they exist, ask for and check master password, else use initial_registration()
    firstTimeFlag = False
    if not os.path.isfile("passwd_file") or not os.path.isfile("master_passwd"):
        initial_registration()
        firstTimeFlag = True
    else:
        check = False
        while not check:
            mass_pass = input("Please input your master password: ")
            check = user_input_is_good(mass_pass)
            if check:
                check_master_password(mass_pass)

    key = retrieve_key()
    encoded = base64.urlsafe_b64encode(key)
    f = CTRFernet(encoded)

    if not firstTimeFlag:
        decrypted = file_decryptor(f)

    repeat = True

    with open("passwd_file", 'wb') as pass_file:

        while repeat:
            check = False
            display_menu()

            user_input = input("Enter the function you wish to use [1-6]: ")

            if user_input == '1':
                check_integrity()
            elif user_input == '2':
                # print("Please enter username, password, and domain, separated by spaces")
                while not check:
                    inp = input("Please enter username, password, and domain, separated by spaces: ")
                    usename_in, passwd_in, dom_in = inp.split(' ')
                    check = user_input_is_good(usename_in) and user_input_is_good(passwd_in) and user_input_is_good(dom_in)
                    if check:
                        register_account(decrypted, usename_in, passwd_in, dom_in)
                    else:
                        print("Problem with input, possible attack detected, please try again")
            elif user_input == '3':
                # print("Please enter username, password, and domain, separated by spaces")
                while not check:
                    inp = input("Please enter username, password, and domain, separated by spaces: ")
                    usename_in, passwd_in, dom_in = inp.split(' ')
                    check = user_input_is_good(usename_in) and user_input_is_good(passwd_in) and user_input_is_good(dom_in)
                    if check:
                        delete_account(decrypted, usename_in, passwd_in, dom_in)
                    else:
                        print("Problem with input, possible attack detected, please try again")
            elif user_input == '4':
                # print("Please enter username, old password, new password, and domain, separated by spaces")
                while not check:
                    inp = input("Please enter username, old password, new password, and domain, separated by spaces: ")
                    usename_in, old_passwd, new_passwd, dom_in = inp.split(' ')
                    check = user_input_is_good(usename_in) and user_input_is_good(old_passwd) and user_input_is_good(new_passwd) and user_input_is_good(dom_in)
                    if check:
                        change_account(decrypted, usename_in, old_passwd, new_passwd, dom_in)
                    else:
                        print("Problem with input, possible attack detected, please try again")
            elif user_input == '5':
                # print("please enter domain")
                while not check:
                    dom_in = input("please enter domain: ")
                    check = user_input_is_good(dom_in)
                    if check:
                        get_password(decrypted, dom_in)
                    else:
                        print("Problem with input, possible attack detected, please try again")
            elif user_input == '6':
                repeat = False
                exit_manager(db, f)
            else:
                input("Selection error. Press any key to try again.")