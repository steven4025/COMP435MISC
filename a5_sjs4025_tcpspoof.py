from scapy.all import *

ip = IP(src="192.0.2.0")  ##Source IP from IP test site provided
ip.dst="152.2.254.254"    ##Dest. IP from IP provided in Piazza

ip/TCP()                  ##create layer IP/TCP

tcp = TCP(sport=1025, dport=80)     ##set source and dest. port

send(ip/tcp)              ##send packet