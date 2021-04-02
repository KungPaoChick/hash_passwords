import hashlib
import os
import argparse
import json
from base64 import b64encode, b64decode


class Hash_Password:

    def __init__(self, login):
        self.username = login[0]
        self.password = login[1]

    def hash_function(self):
        users = {}

        salt = b64encode(os.urandom(64)).decode('utf-8')
        key = b64encode(hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), b64decode(salt.encode('utf-8')), 100000)).decode('utf-8')
        users[self.username] = {
            'password': salt+key,
        }

        with open('user.json', 'w') as f_source:
            json.dump(users, f_source, indent=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Hash Passwords.')

    parser.add_argument('user_pass',
                        nargs=2, metavar='USER_PASSWORDS',
                        action='store', help='Hash Testing. Put Username and password')

    args = parser.parse_args()

    if args.user_pass:
        Hash_Password([x for x in args.user_pass]).hash_function()
