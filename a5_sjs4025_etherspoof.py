from scapy.all import *

packet = Ether(src="1:02:03:04:05:06")/IP()/TCP()   ##creation of packet to be sent
                                                    ##Src MAC is set
                                                    ##IP and TCP taken care of by Scapy

sendp(packet)                                       ##send packet