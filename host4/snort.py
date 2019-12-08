#! /usr/bin/env python3
from kamene.all import *
from netfilterqueue import NetfilterQueue
import os
from datetime import datetime
import math
packet_log = {} # Tracks the time since the last NTP packet per IP
packet_history = {} # Keeps of the times there were problems with a packet
pool_history = {} # Keeps track of the pool history
valid_ref_ids = {"0.0.0.0"} # Valid hostnames and IPs for NTP servers
invalid_pkt_count = {}

# Rejects packets after five bad packets from IP
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if '10.4.8' not in scapy_packet[IP].src:
        return
    if scapy_packet.haslayer(NTP):
        #print("recv")
        #print(scapy_packet[NTP].id)       
        if PIE(scapy_packet):
            print("Accepted Packet")
            packet.accept()
            return
        else:
            if scapy_packet[IP].src in invalid_pkt_count:
                invalid_pkt_count[scapy_packet[IP].src] += 1
                print(invalid_pkt_count[scapy_packet[IP].src])
                if invalid_pkt_count[scapy_packet[IP].src] > 5:
                    print("Rejected Packet")
                    return
            else:
                invalid_pkt_count[scapy_packet[IP].src] = 1
    print("Accepted Packet")
    packet.accept()
            
# packet inspection engine
# if there has been more than 1 ntp packets in the last min
def PIE(packet):
    t1 = poolTimeCheck(packet) 
    t2 = poolHistoryCheck(packet)    
    t3 = refIDCheck(packet)
    print(t1,t2,t3)
    return t1 and t2 and t3

# checks if the packet is being set at a regular interval in the format 2^x
def poolTimeCheck(packet):
    if packet[IP].src in packet_log:
        timeSinceLastPkt = (datetime.now() - packet_log[packet[IP].src]).total_seconds()
        log = math.log2(timeSinceLastPkt)
        #print("projected pool", log)
        pool_history[packet[IP].src].append(round(log))
        diff = round(log)-log 
        if  round(log)-log > 0.35:
            packet_log[packet[IP].src] = datetime.now()
            packet_history[packet[IP].src].append(datetime.now())
            print("ALERT: Invalid Pool Time, the time did not follow to 2^x pattern from IP address: ", packet[IP].src)
            return False
        else:
            packet_log[packet[IP].src] = datetime.now()
            #print("good time check", timeSinceLastPkt)
            
    else:
        packet_log[packet[IP].src] = datetime.now()
        packet_history[packet[IP].src] = []
        pool_history[packet[IP].src] = []
        #print("first packet")
    return True

#Checks if there was a negative change in pool time
# NTP is suppose to go up to max and stay there 
# we check if it is fluctuating
def poolHistoryCheck(packet):
    # we need atleast 2 data points
    if len(pool_history[packet[IP].src]) < 2:
        #print(pool_history[packet[IP].src])
        #print("not enough data for pool hist check")
        return True

    if pool_history[packet[IP].src][-1] < pool_history[packet[IP].src][-2]:
        print("ALERT: Pool decreased from IP address:", packet[IP].src)
        return False
    #print("past pool hist check")
    return True

# checks if the reference ID is a valid address
def refIDCheck(packet):
   if packet[NTP].id not in valid_ref_ids:
       print("ALERT: Invalid Reference from IP address: ", packet[IP].src)
       return False
   #print("valid ref id:", packet[NTP].id)
    

if __name__ == "__main__":
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate the netfilter queue
    queue = NetfilterQueue()
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        # if want to exit, make sure we
        # remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")

# This script was reused from https://www.thepythoncode.com/article/make-dns-spoof-python
