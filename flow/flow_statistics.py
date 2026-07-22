"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Flow Statistics
Description:
Stores runtime information about all flows.
====================================================
"""

from collections import Counter

# ==================================================
# Runtime Flow Tables
# ==================================================

active_flows = {}

completed_flows = []

# ==================================================
# Counters
# ==================================================

total_flows = 0

active_flow_count = 0

completed_flow_count = 0

# ==================================================
# Communication Statistics
# ==================================================

source_counter = Counter()

destination_counter = Counter()

protocol_counter = Counter()

flow_protocol_counter = Counter()