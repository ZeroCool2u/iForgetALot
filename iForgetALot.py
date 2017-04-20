import os.path

def check_integrity():
    # check integrity of files
    # TODO finish implementation
    print("Checking file integrity.")


def register_account(username, password, domain):
    # register a new account
    # TODO finish implementation
    print("Registering a new account.")


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
    print("Generating key")


def check_master_password(master_password):
    # TODO finish implementation
    print("checking master password")


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
    if not os.path.isfile("passwd_file"):
        initial_registration()
    elif not os.path.isfile("master_passwd"):
        initial_registration()
    else:
        check = False
        while not check:
            mass_pass = input("Please input your master password: ")
            check = user_input_is_good(mass_pass)
            if check == True:
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