from collections import Counter
from scapy.all import sniff, IP
from scapy import *

dos_warning = False
dos_attack = False
blacklist = []

def custom_action(packet):
    key = (packet[0][1].src, packet[0][1].dst)
    packet_counts.update([key])
    return ("Packet detected: {} ==> {}".format(packet[0][1].src, packet[0][1].dst))


while True:
    print ("Listening...")
    packet_counts = Counter()
    sniff(lfilter=lambda pkt: IP in pkt and pkt[IP].src not in blacklist, prn=custom_action, timeout=1, iface="eth0")
    for key, count in packet_counts.items():
        if count >= 3:
            if dos_warning == False:
                dos_warning = True
                print ("WARNING: risk of {} currently being under DoS attack from {}.".format(key[1], key[0]))
            else:
                dos_attack = True
                print ("WARNING: DoS attack from {} on {} confirmed, communication from {} will be ignored.".format(key[0], key[1], key[0]))
                blacklist.append(key[0])
                dos_warning = False
                print ("WARNING: {} is now ignored by the IPS, resuming listening.".format(key[0]))
        elif dos_warning == True:
            dos_warning = False
            print ("Risk of DoS went unconfirmed, all clear.")
