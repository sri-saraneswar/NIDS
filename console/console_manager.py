"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Console Manager

Displays

1. Live Status
2. New Attack Alerts
3. Attack Progress
4. Attack Finished
5. Session Summary

=========================================================
"""

from datetime import datetime


# ==========================================================
# Live Status
# ==========================================================

def display_live_status(stats):


    print(

        f"\rPackets : {stats.get('packets',0)} | "

        f"Alerts : {stats.get('alerts',0)} | "

        f"Warnings : {stats.get('warnings',0)} | "

        f"Risk : {stats.get('risk','LOW')}",

        end="",

        flush=True

    )


# ==========================================================
# New Attack
# ==========================================================

def display_alert(packet, attack):

    print("\n")

    print("=" * 65)

    print("🚨  NEW ATTACK DETECTED")

    print("=" * 65)

    print(f"Attack Type     : {attack['attack_type']}")

    print(f"Severity        : {attack['severity']}")

    print(f"Source          : {attack['source_ip']}")

    print(f"Destination     : {attack['destination_ip']}")

    print(f"Protocol        : {packet['protocol']}")

    print(f"Started         : {attack['start_time']}")

    print("=" * 65)


# ==========================================================
# Attack Continuing
# ==========================================================

def display_attack_progress(attack):

    print(

        f"\r{attack['attack_type']} "

        f"continuing... "

        f"Packets : {attack['packet_count']}",

        end="",

        flush=True

    )


# ==========================================================
# Attack Finished
# ==========================================================

def display_finished_attack(attack):

    print("\n")

    print("=" * 65)

    print("✓ ATTACK FINISHED")

    print("=" * 65)

    print(f"Attack Type     : {attack['attack_type']}")

    print(f"Severity        : {attack['severity']}")

    print(f"Source          : {attack['source_ip']}")

    print(f"Destination     : {attack['destination_ip']}")

    print(f"Duration        : {attack['duration']:.2f} sec")

    print(f"Packets         : {attack['packet_count']}")

    if attack.get("details"):

        print("\nDetails")

        for key, value in attack["details"].items():

            print(f"{key:20}: {value}")

    print("=" * 65)


# ==========================================================
# Overall Session Summary
# ==========================================================

def display_session_summary(summary):

    print("\n")

    print("=" * 70)

    print("SESSION SUMMARY")

    print("=" * 70)

    print(f"Session ID          : {summary['session_id']}")

    print(f"Start Time          : {summary['start_time']}")

    print(f"End Time            : {summary['end_time']}")

    print(f"Duration            : {summary['duration']:.2f} sec")

    print(f"Packets             : {summary['packets']}")

    print(f"Flows               : {summary['flows']}")

    print(f"Alerts              : {summary['alerts']}")

    print(f"Warnings            : {summary['warnings']}")

    print(f"Highest Risk        : {summary['risk']}")

    print(f"Unique Attacks      : {summary['unique_attacks']}")

    print("=" * 70)


# ==========================================================
# Attack History
# ==========================================================

def display_attack_history(attacks):

    if not attacks:

        print("\nNo attacks detected.")

        return

    print("\n")

    print("=" * 70)

    print("ATTACK HISTORY")

    print("=" * 70)

    for attack in attacks:

        print()

        print(f"Attack ID      : {attack['alert_id']}")

        print(f"Type           : {attack['attack_type']}")

        print(f"Severity       : {attack['severity']}")

        print(f"Source         : {attack['source_ip']}")

        print(f"Destination    : {attack['destination_ip']}")

        print(f"Packets        : {attack['packets']}")

        print(f"Start          : {attack['start_time']}")

        print(f"End            : {attack['end_time']}")

        if attack.get("details"):

            print("\nDetails")

            for key, value in attack["details"].items():

                print(f"   {key:20}: {value}")

        print("-" * 70)