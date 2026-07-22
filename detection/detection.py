"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Detection Engine

Description:
Coordinates the intrusion detection process by
applying IDS rules, updating network statistics,
and returning the detection result.
====================================================
"""

from detection.rules import detect_rules

from detection.statistics import (
    update_statistics,
    should_print_summary
)


# ==================================================
# Detection Engine
# ==================================================

def detect(packet_info):
    """
    Applies IDS rules to a captured packet,
    updates network statistics, and returns
    the detection result.

    Parameters
    ----------
    packet_info : dict
        Packet information received from the
        Capture Module.

    Returns
    -------
    dict
        Detection result containing:
        - status
        - severity
        - rule_id
        - attack
        - reason
    """

    # ----------------------------------------------
    # Apply Detection Rules
    # ----------------------------------------------

    result = detect_rules(packet_info)

    # ----------------------------------------------
    # Update Statistics
    # ----------------------------------------------

    update_statistics(packet_info, result)

    # ----------------------------------------------
    # Return Detection Result
    # ----------------------------------------------

    return result


# ==================================================
# Security Summary Trigger
# ==================================================

def summary_required():
    """
    Determines whether the security summary
    should be displayed.

    Returns
    -------
    bool
        True if the configured summary interval
        has been reached.
    """

    return should_print_summary()