#!/usr/bin/python
from pwn import *

context.log_level = 'debug'


class VpnClient:
    process_binary = r'/usr/sbin/openconnect'
    process_args = r'--protocol'
    name_prompt = r'Username: '
    password_prompt = r'Password: '
    domain_prompt = r'Enter DOMAIN\Username'
    login_prompt = r'Enter login credentials'

    def __init__(self, domain, username, password, url, protocol):
        self._connection = None
        self._timeout = 1.0
        self._domain = domain
        self._username = username
        self._password = password
        self._url = url
        self._protocol = protocol

    def connect(self):
        self.process_args = '='.join([self.process_args, self._protocol])
        self._connection = process([self.process_binary, self.process_args, self._url])
        self._connection.sendlineafter(self.name_prompt, r'%s\%s' % (self._domain, self._username))
        self._connection.sendlineafter(self.password_prompt, self._password)
        self._connection.sendlineafter(self.password_prompt, self._password)
        self._connection.interactive()
        return self


if __name__ == '__main__':
    client = VpnClient(
        domain='domain.local',
        username='user.name',
        password='Password',
        url='https://vpn.domain.com',
        protocol='gp'
    ).connect()
    