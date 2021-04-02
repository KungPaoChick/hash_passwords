import json
import hashlib
import argparse
from base64 import b64decode


class Logger:

    def __init__(self, credentials):
        self.username = credentials[0]
        self.password = credentials[1]

    def login(self):
        with open('user.json', 'r', encoding='utf-8') as j_source:
            source = json.load(j_source)

        for info in source:
            if self.username == info:
                new_key = hashlib.pbkdf2_hmac('sha256', self.password.encode('utf-8'), b64decode(source[self.username]['password'][:88].encode('utf-8')), 100000)

                if b64decode(source[self.username]['password'][88:].encode('utf-8')) == new_key:
                    print('Successfully logged in.')
                else:
                    print('Wrong Password.')
            else:
                print('Wrong Username.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('user_pass',
                        nargs=2, metavar='USER_PASS',
                        action='store', help='login')

    args = parser.parse_args()

    if args.user_pass:
        Logger([x for x in args.user_pass]).login()
