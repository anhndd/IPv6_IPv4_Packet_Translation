from scapy.all import *

def process_packet(pkt):
    print(pkt.summary())
    # pkt.show()


sniff(prn=lambda x: process_packet(x),filter="tcp")

# a=sniff(filter="tcp")
# a.nsummary()

