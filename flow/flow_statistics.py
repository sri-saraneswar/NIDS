"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Flow Statistics

Stores runtime flow information.

====================================================
"""


from collections import Counter



# Active flows

active_flows = {}



# Completed flows

completed_flows = []



# Counters

total_flows = 0


active_flow_count = 0


completed_flow_count = 0




# Communication statistics

source_counter = Counter()


destination_counter = Counter()


protocol_counter = Counter()