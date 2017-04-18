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


def initial_registration(master_password):
    print("Generating key")


def display_menu():
    print("1. Check integrity")
    print("2. Register account")
    print("3. Delete account")
    print("4. Change account")
    print("5. Get password")
    print("6. Exit")


if __name__ == '__main__':
    # TODO check for need to register for password manager

    # check for passwd_file and master_passwd
    # if they exist, ask for and check master password, else use initial_registration()

    repeat = True

    while repeat:
        display_menu()

        user_input = input("Enter the function you wish to use [1-6]: ")

        if user_input == 1:
            check_integrity()
        elif user_input == 2:
            print("Please enter username, password, and domain")
            # TODO collect input
            register_account()
        elif user_input == 3:
            print("Please enter username, password, and domain")
            # TODO collect input
            delete_account()
        elif user_input == 4:
            print("Please enter username, old password, new password, and domain")
            # TODO collect input
            change_account()
        elif user_input == 5:
            print("please enter domain")
            get_password()
        elif user_input == 6:
            repeat = False
            exit_manager()
        else:
            input("Selection error. Press any key to try again.")