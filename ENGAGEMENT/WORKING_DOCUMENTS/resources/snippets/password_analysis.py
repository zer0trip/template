#!/usr/bin/env python
import argparse
import operator
from sys import argv, exit


class Result:
    def __init__(self, ntlm_hash):
        self.hash = ntlm_hash
        self.count = 0
        self.password = ''
        self.usernames = []

    def __repr__(self):
        return "TOTAL %d HASH %s PASSWORD %s TOTAL USERS %d" % (self.count, self.hash, self.password, len(self.usernames))
        #return "%d %s %s" % (self.count, self.hash, self.password)


def analyze_cracked(file_path, results):
    for line in open(file_path):
        line = str(line.strip().encode('ascii'))
        # hash:password
        if ':' not in line:
            continue
        items = line.split(':')
        ntlm = items[0].lower()
        passwd = items[1]
        if ntlm not in results.keys():
            r = Result(ntlm_hash=ntlm)
            results[ntlm] = r
            results[ntlm].count += 1
        results[ntlm].password = passwd
    return results


def analyze_hashes(file_path):
    results = {}
    for line in open(file_path):
        line = str(line.strip().encode('ascii')).lower()
        # domain\user.last:int:sha1:ntlm:::
        items = line.split(':')
        user = items[0]
        ntlm = items[3]
        if ntlm not in results.keys():
            r = Result(ntlm_hash=ntlm)
            results[ntlm] = r
        results[ntlm].count += 1
        results[ntlm].usernames.append(user)
    return results


def sort_hashes(results):
    return sorted(list(results.values()), key=operator.attrgetter("count"), reverse=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description='Hash analytics')
    try:
        parser.add_argument('-ntds', action='store', help='Input file with ntds hashes')
        parser.add_argument('-cracked', action='store', help='Input file with cracked hashes')

        if len(argv) == 1:
            parser.print_help()
            exit(1)
        options = parser.parse_args()
        results = analyze_hashes(options.ntds)
        results = analyze_cracked(options.cracked, results)
        results = sort_hashes(results)
        print('\n'.join(str(results).split(',')).replace('[', '').replace(']', ''))

    except Exception as err:
        print(err)
