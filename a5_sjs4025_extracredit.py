from scapy.all import *

def echo (pkt):
	if str(pkt.getlayer(ICMP).type) == "8":				##filters ICMP packets
		reply_dest=pkt[IP].src					##take source IP of ICMP request, store in variable reply_dest
		reply_src=pkt[IP].dst					##take dest. IP of ICMP request, store in variable reply_src
		ip=IP(src=reply_src)					##set source of spoof ICMP reply
		ip.dst=reply_dest					##set dest. of spoof ICMP reply
		reply_seq=pkt[ICMP].seq					##get seq number of ICMP request, store in variable reply_seq
		reply_id=pkt[ICMP].id					##get id number of ICMP request, store in variable reply_id
		icmp=ICMP(seq=reply_seq,id=reply_id,type=0)		##create ICMP layer, type is echo-reply
		echo_reply=ip/icmp					##create echo-reply packet
		send(echo_reply)					##send packet
	

sniff(filter="icmp",prn=echo,timeout=20)				##sniff function, filtering ICMP packets, callback fn is defined fn
