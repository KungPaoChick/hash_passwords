import os
import json
import colorama
from getpass import getpass
from colorama import Fore, Style
from hashlib import pbkdf2_hmac
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from base64 import b64encode, b64decode


class Register:

    def __init__(self, register_username, password):
        self.username = register_username[0]
        self.password = password

    def hash_password(self):
        users = {}

        salt = b64encode(os.urandom(64)).decode('utf-8')
        key = b64encode(pbkdf2_hmac('sha256', self.password.encode(
            'utf-8'), b64decode(salt.encode('utf-8')), 100000)).decode('utf-8')

        users = {}
        users['user'] = []

        users['user'].append({
            'username': self.username,
            'password': salt+key,
        })
        with open('user.json', 'w', encoding='utf-8') as f_source:
            json.dump(users, f_source, indent=2)
            for dict in users['user']:
                print(Fore.GREEN, f"[*] {dict['username']} has been added", Style.RESET_ALL)


class Login:

    def __init__(self, login_username, password):
        self.username = login_username[0]
        self.password = password

    def verify_user(self):
        if not os.path.exists(os.path.join(os.getcwd(), 'user.json')):
            print(Fore.YELLOW, '[!] No user recorded. Register first using (-r Username) argument.',
                  Style.RESET_ALL)
        else:
            with open('user.json', 'r', encoding='utf-8') as j_source:
                source = json.load(j_source)

            for dict in source['user']:
                if not self.username == dict['username']:
                    print(Fore.RED, '[!!] Authenticaion Failed! Username or Password is incorrect.', Style.RESET_ALL)
                else:
                    new_key = pbkdf2_hmac('sha256', self.password.encode(
                        'utf-8'), b64decode(dict['password'][:88].encode('utf-8')), 100000)

                    if not b64decode(dict['password'][88:].encode('utf-8')) == new_key:
                        print(Fore.RED, '[!!] Authentication Failed! Username or Password is incorrect.', Style.RESET_ALL)
                        return False
                    else:
                        print(Fore.GREEN, f"[*] Authentication Success! User {dict['username']}", Style.RESET_ALL)
                        return True

class JSON_Data:

    def __init__(self, filename='user.json'):
        self.filename = filename

    def read(self):
        with open(self.filename, 'r', encoding='utf-8') as j_source:
            return json.loads(j_source)

    def write(self, dataset):
        with open(self.filename, 'w', encoding='utf-8') as f_source:
            return json.dump(dataset, f_source, indent=2)


if __name__ == '__main__':
    colorama.init()
    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                            description='Hash Passwords.')

    parser.add_argument('-r', '--register',
                        nargs=1, metavar='REGISTER', type=str,
                        action='store', help='Register Account (Username)')

    parser.add_argument('-l', '--login',
                        nargs=1, metavar='LOGIN', type=str,
                        action='store', help='Login Account (Username)')

    args = parser.parse_args()
    if args.register:
        try:
            while True:
                passwd_input = getpass('Enter Password: ')
                confirm_passwd = getpass('Confirm Password: ')

                if not confirm_passwd == passwd_input:
                    print(Fore.RED, '[!!] Passwords do not match', Style.RESET_ALL)
                else:
                    Register([x for x in args.register], passwd_input).hash_password()        
                    break
        except KeyboardInterrupt:
            print('\nStopped!')

    if args.login:
        try:
            temp = 3
            while temp > 0:
                passwd_input = getpass('Enter Password: ')

                if not Login([x for x in args.login], passwd_input).verify_user():
                    temp -= 1
                else:
                    break

            if temp == 0:
                print(Fore.RED, '[!!] Too many retries.', Style.RESET_ALL)
        except KeyboardInterrupt:
            print('\nStopped!')
