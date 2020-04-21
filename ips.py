from collections import Counter
from scapy.all import sniff, IP
from scapy import *

dos_warning = False
blacklist = []

def pkt_detection(packet):
    key = (packet[0][1].src, packet[0][1].dst])
    packet_counts.update([key])
    return ("Packet detected: {} ==> {}".format(packet[0][1].src, packet[0][1].dst))


while True:
    print ("Listening...")
    packet_counts = Counter()
    sniff(lfilter=lambda pkt: IP in pkt and pkt[IP].src not in blacklist, prn=pkt_detection, timeout=1, iface=["eth0", "eth1"])
    for key, count in packet_counts.items():
        if count >= 5:
            if dos_warning == False:
                dos_warning = True
                print ("WARNING: {} might currently be under DoS attack from {}.".format(key[1], key[0]))
            else:
                print ("WARNING: DoS attack from {} on {} confirmed, communication from {} will be ignored.".format(key[0], key[1], key[0]))
                blacklist.append(key[0])
                dos_warning = False
                print ("WARNING: {} is now ignored by the IPS, resuming listening.".format(key[0]))
        elif dos_warning == True:
            dos_warning = False
            print ("Risk of DoS attack went unconfirmed, all clear.")
