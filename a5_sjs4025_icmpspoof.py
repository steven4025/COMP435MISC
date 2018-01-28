from scapy.all import *

ip = IP(src="192.0.2.0")        ##Source IP address from test IP address site
ip.dst = "203.0.113.0"          ##Dest. IP address from test IP address site

packet = ip/ICMP()/"Hello!"     ##create packet with layer IP/ICMP
send(packet)                    ##send packet