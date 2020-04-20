from collections import Counter
from scapy.all import sniff

dos_warning = False
dos_attack = False
pktID = -1
blacklist = []

def custom_action(packet):
    key = (packet[0][1].src, packet[0][1].dst)
    packet_counts.update([key])
    pktID += 1
    return f"Packet #{pktID}: {packet[0][1].src} ==> {packet[0][1].dst}"


while True:
    packet_counts = Counter()
    sniff(filter="ip", prn=custom_action, timeout=1)
    sniff(lfilter=lambda pkt: IP in pkt and pkt[IP].src not in blacklist, prn=custom_action, timeout=1)
    for key, count in packet_count.items():
        if count >= 3:
            if dos_warning == False:
                dos_warning = True
                print f"WARNING: risk of {key[1]} currently being under DoS attack from {key[0]}."
            else:
                dos_attack = True
                print f"WARNING: DoS attack from {key[0]} on {key[1]} confirmed, communication from {key[0]} will be ignored."
                blacklist.append(key[0])
                dos_warning = False
                print f"WARNING: {key[0]} is now ignored by the IPS, resuming monitoring."
        elif dos_warning == True:
            dos_warning = False
            print "Risk of DoS went unconfirmed, all clear."