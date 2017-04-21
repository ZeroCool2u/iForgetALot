import gc
import os.path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
salt = bytes([42])
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=256,
    salt=salt,
    iterations=9001,
    backend=backend
)

def check_integrity():
    # check integrity of files
    # TODO finish implementation
    print("Checking file integrity.")


def register_account(username, password, domain):
    """Register a new account"""
    # TODO finish implementation
    with open("passwd_file", 'wb') as pass_file:
        print("Registering a new account.")
        pwfData = bytearray(username, 'utf-8').append(bytearray(' ', 'utf-8')).append(
            bytearray(password, 'utf-8').append(bytearray(' ', 'utf-8'))).append(bytearray(domain, 'utf-8'))
        pass_file.write(pwfData)
        del username
        del password
        del domain
        del pwfData
        gc.collect()
        print('Registration and cleanup complete.')


def delete_account(username, password, domain):
    # delete account
    # TODO finish implementation
    print("Deleting account.")


def change_account(username, old_password, new_password, domain):
    # change the password of an account already in the manager
    # TODO finish implementation
    print("Changing password in account.")


def get_password(domain):
    # get a password for an account in the manager
    # TODO finish implementation
    print("Retrieving password.")


def exit_manager():
    # exit the program
    # TODO finish implementation
    print("Exiting program. Goodbye.")


def initial_registration():
    # TODO finish implementation
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


def check_master_password(master_password):
    # TODO finish implementation
    print("checking master password")
    with open("master_passwd", 'rb') as  mass_pass_file:
        keyfiledata = mass_pass_file.read()
        old_salt = keyfiledata[:len(salt)]
        # ret_salt = mass_pass_file.read(len(salt))
        key = keyfiledata[len(salt):]
        # key = mass_pass_file.read()
        master_password = bytes(master_password, 'utf-8')
        if kdf.verify(master_password, key):
            print("Password accepted")
        else:
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


if __name__ == '__main__':
    # check for passwd_file and master_passwd
    # if they exist, ask for and check master password, else use initial_registration()
    if not os.path.isfile("passwd_file") or not os.path.isfile("master_passwd"):
        initial_registration()
    else:
        check = False
        while not check:
            mass_pass = input("Please input your master password: ")
            check = user_input_is_good(mass_pass)
            if check:
                check_master_password(mass_pass)

    repeat = True

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
                    register_account(usename_in, passwd_in, dom_in)
                else:
                    print("Problem with input, possible attack detected, please try again")
        elif user_input == '3':
            # print("Please enter username, password, and domain, separated by spaces")
            while not check:
                inp = input("Please enter username, password, and domain, separated by spaces: ")
                usename_in, passwd_in, dom_in = inp.split(' ')
                check = user_input_is_good(usename_in) and user_input_is_good(passwd_in) and user_input_is_good(dom_in)
                if check:
                    delete_account(usename_in, passwd_in, dom_in)
                else:
                    print("Problem with input, possible attack detected, please try again")
        elif user_input == '4':
            # print("Please enter username, old password, new password, and domain, separated by spaces")
            while not check:
                inp = input("Please enter username, old password, new password, and domain, separated by spaces: ")
                usename_in, old_passwd, new_passwd, dom_in = inp.split(' ')
                check = user_input_is_good(usename_in) and user_input_is_good(old_passwd) and user_input_is_good(new_passwd) and user_input_is_good(dom_in)
                if check:
                    change_account(usename_in, old_passwd, new_passwd, dom_in)
                else:
                    print("Problem with input, possible attack detected, please try again")
        elif user_input == '5':
            # print("please enter domain")
            while not check:
                dom_in = input("please enter domain: ")
                check = user_input_is_good(dom_in)
                if check:
                    get_password(dom_in)
                else:
                    print("Problem with input, possible attack detected, please try again")
        elif user_input == '6':
            repeat = False
            exit_manager()
        else:
            input("Selection error. Press any key to try again.")