#!/usr/bin/env python
from itertools import compress, product, chain, combinations
from sys import argv, exit
import argparse


def generate_list_limit(word_list, limit=12, filter=False):
    for subset in combinations(word_list, limit):
        line = str(''.join(list(subset)).encode('ascii'))
        if (filter != False and len(line) == int(filter)) or (filter == False):
            print(line)


def generate_list_all(file_path, filter=False):
    word_list = str(open(file_path, 'r').read().encode('ascii')).split('\n')
    for subset in all_subsets(word_list):
        line = str(''.join(list(subset)).encode('ascii'))
        if (filter != False and len(line) == int(filter)) or (filter == False):
            print(line)


def all_subsets(ss):
    return chain(*map(lambda x: combinations(ss, x), range(0, len(ss) + 1)))


def parse_base(file_path, upper=False, lower=False, reverse=False):
    output = []
    result = ''

    if upper == False and lower == False:
        result += open(file_path, 'r').read()
    if upper:
        result += open(file_path, 'r').read().upper()
    if lower:
        result += open(file_path, 'r').read().lower()
    output += list(result.replace(' ', '').split('\n'))
    while '' in output:
        output.remove('')
    if reverse:
        normal = output
        output.reverse()
        output += normal

    return output


def filter_size(file_path, limit=8):
    for line in open(file_path):
        line = str(line.strip().encode('ascii'))
        if len(line) >= limit:
            print(line)


def filter_size_strict(file_path, limit=8):
    for line in open(file_path):
        line = str(line.strip().encode('ascii'))
        if len(line) == limit:
            print(line)


def check_word(file_path, word):
    for line in open(file_path):
        line = str(line.strip().encode('ascii'))
        if len(line) == str(word).encode('ascii'):
            print('MATCH: %s' % line)
            exit(1)


def filter_list_match(file_path, filter_path):
    for line in open(file_path):
        line = str(line.strip().encode('ascii'))
        for f_line in open(filter_path):
            f_line = str(f_line.strip().encode('ascii'))
            if f_line in line:
                print(line)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description='Word list generator')
    try:
        parser.add_argument('-file', action='store', help='Input file of base word list')
        parser.add_argument('-mutate', default=2, action='store', help='Mutate length')
        parser.add_argument('-mutateall', default=False, action='store', help='Mutate length of all the list')
        parser.add_argument('-wordlength', default=False, action='store', help='Word length to generate')
        parser.add_argument('-filter', default=False, action='store', help='Filter word length')
        parser.add_argument('-filterstrict', default=False, action='store', help='Filter word length *strict')
        parser.add_argument('-filterlist', default=False, action='store', help='Filter word matching via list *strict')
        parser.add_argument('-checkword', default=False, action='store', help='Check for word in dictionary')

        if len(argv) == 1:
            parser.print_help()
            exit(1)
        options = parser.parse_args()
        if options.filter:
            filter_size(options.file, int(options.filter))
        elif options.filterstrict:
            filter_size_strict(options.file, int(options.filterstrict))
        elif options.checkword:
            check_word(options.file, options.checkword)
        elif options.mutateall:
            generate_list_all(options.file, options.wordlength)
        elif options.filterlist:
            filter_list_match(options.file, options.filterlist)
        else:
            generate_list_limit(parse_base(options.file), int(options.mutate), options.wordlength)

    except Exception as err:
        print(err)
		
"""
python generator/generate.py -file keywalk.txt -mutate 2 >> dictionary.txt
python generator/generate.py -file keywalk.txt -mutate 3 >> dictionary.txt
python generator/generate.py -file keywalk.txt -mutate 4 >> dictionary.txt
# keywalk left
qaz
QAZ
zaq
ZAQ
!QAZ
1qaz
ZAQ!
zaq1
wsx
xsw
WSX
XSW
2wsx
xsw2
@WSX
XSW@
edc
cde
EDC
CDE
3edc
cde3
#EDC
CDE#
rfv
vfr
RFV
VFR
4rfv
rfv4
$RFV
VFR$
tgb
bgt
TGB
BGT
%TGB
BGT%
5tgb
bgt5
yhn
nhy
YHN
NHY
6yhn
nhy6
^YHN
NHY^
ujm
mju
UJM
MJU
7ujm
mju7
&UJM
MJU&
ik,
,ki
IK<
<KI
8ik,
,ki8
*IK<
<KI*
ol.
.lo
OL>
>LO
9ol.
.lo9
(OL>
>LO(
p;/
/;p
P:?
?:P
0p;/
/;p0
)P:?
?:P)

# keywalk right
pl,
,lp
-pl,
,lp-
PL<
<LP
_PL<
<LP_
okm
mko
OKM
MKO
0okm
mko0
)OKM
MKO)
ijn
nji
IJN
NJI
9ijn
nji9
(IJN
NJI(
uhb
bhu
UHB
BHU
8uhb
bhu8
*UHB
BHU*
ygv
vgy
YGV
VGY
7ygv
vgy7
&YGV
VGY&
tfc
cft
TFC
CFT
6tfc
cft6
^TFC
CFT^
rdx
xdr
RDX
XDR
5rdx
xdr5
%RDX
XDR%
esz
zse
ESZ
ZSE
4esz
zse4
$ESZ
ZSE$
wa
aw
3wa
aw3
WA
AW
#WA
AW#

# common 
Winter
Spring
Summer
Fall
Autumn
Password
Pawrd
Passwrd
January
February
March
April
May
June
July
August
September
October
November
December
Master
Dragon
Monkey
Shadow
Qwerty
Iloveyou
Thankyou
Welcome
Baseball
Football
Letmein
Abc
Mustang
Access
Superman
Batman
Qwertyuiop
Qweasd
Jesus
Ninja
God
"""


		