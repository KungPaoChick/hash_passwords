import hashlib
import os
import argparse
import json
import colorama
from base64 import b64encode, b64decode


class Register:

    def __init__(self, register):
        self.username = register[0]
        self.password = register[1]

    def hash_password(self):
        users = {}

        salt = b64encode(os.urandom(64)).decode('utf-8')
        key = b64encode(hashlib.pbkdf2_hmac('sha256', self.password.encode(
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
                print(f"{dict['username']} has been added")


class Login:

    def __init__(self, login):
        self.username = login[0]
        self.password = login[1]

    def verify_user(self):
        if not os.path.exists(os.path.join(os.getcwd(), 'user.json')):
            print(colorama.Fore.YELLOW,
                  '[!] No user recorded. Register first using (-l Username Password) argument.',
                  colorama.Style.RESET_ALL)
        else:
            with open('user.json', 'r', encoding='utf-8') as j_source:
                source = json.load(j_source)

            for dict in source['user']:
                if not self.username == dict['username']:
                    print(colorama.Fore.RED,
                          '[!!] Authenticaion Failed! Username or Password is incorrect.',
                          colorama.Style.RESET_ALL)
                else:
                    new_key = hashlib.pbkdf2_hmac('sha256', self.password.encode(
                        'utf-8'), b64decode(dict['password'][:88].encode('utf-8')), 100000)

                    if not b64decode(dict['password'][88:].encode('utf-8')) == new_key:
                        print(colorama.Fore.RED,
                              '[!!] Authentication Failed! Username or Password is incorrect.',
                              colorama.Style.RESET_ALL)
                    else:
                        print(colorama.Fore.GREEN,
                              f"[*] Autehentication Success! User {dict['username']}",
                              colorama.Style.RESET_ALL)


if __name__ == '__main__':
    colorama.init()
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Hash Passwords.')

    parser.add_argument('-r', '--register',
                        nargs=2, metavar='REGISTER',
                        action='store', help='Register Account (Username & Password)')

    parser.add_argument('-l', '--login',
                        nargs=2, metavar='LOGIN',
                        action='store', help='Login Account (Username & Password)')

    args = parser.parse_args()

    if args.register:
        Register([x for x in args.register]).hash_password()

    if args.login:
        Login([x for x in args.login]).verify_user()
