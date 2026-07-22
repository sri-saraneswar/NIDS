"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Detection State

Stores temporary information required
for behaviour based detection.

====================================================
"""


from collections import defaultdict, deque



# ICMP packet history

icmp_history = defaultdict(deque)



# Port access history

port_history = defaultdict(deque)



# SYN tracking

syn_history = defaultdict(deque)



# UDP tracking

udp_history = defaultdict(deque)