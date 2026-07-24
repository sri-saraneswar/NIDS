"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Console Manager

Displays:
    1. Banner
    2. Live Status
    3. New Attack Alerts
    4. Attack Progress
    5. Attack Finished
    6. Session Summary
    7. Attack History Table
    8. Database Status

Uses ANSI escape codes for color output.

=========================================================
"""


import sys
import io

from datetime import datetime


# Configure stdout for UTF-8 on Windows
try:
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding="utf-8",
        errors="replace"
    )
except Exception:
    pass





# =====================================================
# ANSI Color Codes
# =====================================================


class Color:
    """ANSI escape code constants."""

    RESET = "\033[0m"

    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"




# =====================================================
# Severity Color Mapping
# =====================================================


def severity_color(severity):
    """Return ANSI color for a severity level."""

    colors = {
        "CRITICAL": Color.RED + Color.BOLD,
        "HIGH": Color.RED,
        "MEDIUM": Color.YELLOW,
        "LOW": Color.GREEN
    }

    return colors.get(
        severity,
        Color.WHITE
    )




# =====================================================
# Risk Color Mapping
# =====================================================


def risk_color(risk):
    """Return ANSI color for a risk level."""

    colors = {
        "CRITICAL": Color.RED + Color.BOLD,
        "HIGH": Color.RED,
        "MEDIUM": Color.YELLOW,
        "LOW": Color.GREEN,
        "SAFE": Color.GREEN
    }

    return colors.get(
        risk,
        Color.GREEN
    )




# =====================================================
# Format Helpers
# =====================================================


def format_bytes(num_bytes):
    """Format byte count to human-readable string."""

    if num_bytes < 1024:
        return f"{num_bytes} B"

    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"

    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"

    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f} GB"



def format_time(dt):
    """Format datetime to HH:MM:SS string."""

    if isinstance(dt, datetime):
        return dt.strftime("%H:%M:%S")

    return str(dt) if dt else "--:--:--"



def format_duration(seconds):
    """Format seconds to human-readable duration."""

    if seconds is None:
        return "N/A"

    if seconds < 60:
        return f"{seconds:.1f}s"

    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"

    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"





# ==========================================================
# Banner
# ==========================================================


def display_banner(interface="Unknown",
                   version="3.0",
                   author="Sri Saraneswar"):
    """
    Display the NIDS startup banner.

    Args:
        interface: Network interface name.
        version: IDS version string.
        author: Author name.
    """

    banner = f"""
{Color.CYAN}{Color.BOLD}
  ================================================================

    _   _ _____ _____   _____
   | \\ | |_   _|  __ \\ / ____|
   |  \\| | | | | |  | | (___
   | . ` | | | | |  | |\\___ \\
   | |\\  |_| |_| |__| |____) |
   |_| \\_|_____|_____/|_____/

   Network Intrusion Detection System

  ================================================================
{Color.RESET}
{Color.DIM}  Version     : {version}
  Author      : {author}
  Interface   : {interface}
  Mode        : Promiscuous
  Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Press CTRL+C to stop{Color.RESET}

{Color.CYAN}{'=' * 65}{Color.RESET}
"""

    print(banner)





# ==========================================================
# Live Status
# ==========================================================


def display_live_status(stats):
    """
    Display a single-line live status bar.

    Overwrites the current line using \r.

    Args:
        stats: Statistics dictionary.
    """

    packets = stats.get("packets", 0)
    alerts = stats.get("alerts", 0)
    warnings = stats.get("warnings", 0)
    risk = stats.get("risk", "LOW")

    r_color = risk_color(risk)

    print(
        f"\r{Color.CYAN}Packets{Color.RESET}"
        f" : {packets:,} | "
        f"{Color.RED}Alerts{Color.RESET}"
        f" : {alerts} | "
        f"{Color.YELLOW}Warnings{Color.RESET}"
        f" : {warnings} | "
        f"Risk : {r_color}{risk}{Color.RESET}"
        f"     ",
        end="",
        flush=True
    )





# ==========================================================
# New Attack Alert
# ==========================================================


def display_alert(packet, attack):
    """
    Display a new attack detection banner.

    Args:
        packet: Packet dictionary.
        attack: Attack dictionary.
    """

    severity = attack.get("severity", "LOW")
    s_color = severity_color(severity)

    print(f"\n")
    print(f"{Color.RED}{Color.BOLD}"
          f"{'=' * 65}")
    print(f"  [!] NETWORK EVENT")
    print(f"{'=' * 65}"
          f"{Color.RESET}")

    print(f"  Attack Type   : "
          f"{Color.BOLD}"
          f"{attack.get('attack_type', 'Unknown')}"
          f"{Color.RESET}")

    print(f"  Severity      : "
          f"{s_color}"
          f"{severity}"
          f"{Color.RESET}")

    print(f"  Source        : "
          f"{attack.get('source_ip', '?')}")

    print(f"  Destination   : "
          f"{attack.get('destination_ip', '?')}")

    print(f"  Protocol      : "
          f"{packet.get('protocol', '?')}")

    print(f"  Status        : "
          f"{Color.RED}ACTIVE{Color.RESET}")

    print(f"  Packet Count  : "
          f"{attack.get('packet_count', 1)}")

    risk = attack.get("severity", "LOW")
    r_color = risk_color(risk)

    print(f"  Risk          : "
          f"{r_color}{risk}{Color.RESET}")

    # Show attack details if available

    details = attack.get("details", {})

    if details:

        print(f"  {'─' * 40}")

        for key, value in details.items():

            display_key = key.replace(
                "_", " "
            ).title()

            print(
                f"  {display_key:16}: {value}"
            )

    print(f"{Color.RED}"
          f"{'=' * 65}"
          f"{Color.RESET}")





# ==========================================================
# Attack Continuing
# ==========================================================


def display_attack_progress(attack):
    """
    Display attack progress on a single line.

    Args:
        attack: Attack dictionary with current stats.
    """

    attack_type = attack.get(
        "attack_type", "Unknown"
    )

    packets = attack.get(
        "packet_count", 0
    )

    # Calculate duration

    start = attack.get("start_time")

    if start:
        duration = (
            datetime.now() - start
        ).total_seconds()
    else:
        duration = 0

    print(
        f"\r{Color.YELLOW}>{Color.RESET} "
        f"{attack_type} "
        f"in progress | "
        f"Packets: {packets} | "
        f"Duration: {format_duration(duration)}"
        f"          ",
        end="",
        flush=True
    )





# ==========================================================
# Attack Finished
# ==========================================================


def display_finished_attack(attack):
    """
    Display attack session completed banner.

    Args:
        attack: Finished attack dictionary.
    """

    print(f"\n")
    print(f"{Color.GREEN}{Color.BOLD}"
          f"{'=' * 65}")
    print(f"  [+] ATTACK SESSION COMPLETED")
    print(f"{'=' * 65}"
          f"{Color.RESET}")

    print(f"  Attack ID     : "
          f"{attack.get('alert_id', 'N/A')}")

    print(f"  Attack Type   : "
          f"{attack.get('attack_type', 'Unknown')}")

    print(f"  Severity      : "
          f"{severity_color(attack.get('severity', 'LOW'))}"
          f"{attack.get('severity', 'LOW')}"
          f"{Color.RESET}")

    print(f"  Source        : "
          f"{attack.get('source_ip', '?')}")

    print(f"  Destination   : "
          f"{attack.get('destination_ip', '?')}")

    duration = attack.get("duration", 0)

    print(f"  Duration      : "
          f"{format_duration(duration)}")

    print(f"  Packets       : "
          f"{attack.get('packet_count', 0)}")

    print(f"  Status        : "
          f"{Color.GREEN}FINISHED{Color.RESET}")

    # Show details if available

    details = attack.get("details", {})

    if details:

        print(f"  {'─' * 40}")

        for key, value in details.items():

            display_key = key.replace(
                "_", " "
            ).title()

            print(
                f"  {display_key:16}: {value}"
            )

    print(f"{Color.GREEN}"
          f"{'=' * 65}"
          f"{Color.RESET}")





# ==========================================================
# Session Summary Report
# ==========================================================


def display_session_summary(summary):
    """
    Display the professional session summary report.

    Called on Ctrl+C graceful shutdown.

    Args:
        summary: Session dictionary from session.to_dict().
    """

    if not summary:
        print("\nNo session data available.")
        return


    w = 65


    print(f"\n")
    print(f"{Color.CYAN}{Color.BOLD}"
          f"{'═' * w}")
    print(f"{'SESSION SUMMARY REPORT':^{w}}")
    print(f"{'═' * w}"
          f"{Color.RESET}")


    # ── Session Info ───────────────────────────

    print(f"\n  Session ID        : "
          f"{Color.BOLD}"
          f"{summary.get('session_id', 'N/A')}"
          f"{Color.RESET}")

    start = summary.get("start_time")
    end = summary.get("end_time")

    print(f"  Start Time        : "
          f"{start}")

    print(f"  End Time          : "
          f"{end}")

    duration = summary.get("duration", 0)

    print(f"  Duration          : "
          f"{format_duration(duration)}")

    print(f"  Interface         : "
          f"{summary.get('interface', 'Unknown')}")



    # ── Traffic Statistics ─────────────────────

    print(f"\n{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")

    print(f"  {Color.BOLD}"
          f"TRAFFIC STATISTICS"
          f"{Color.RESET}")

    print(f"{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")

    packets = summary.get("packets", 0)
    total_bytes = summary.get("total_bytes", 0)

    pps = (
        packets / duration
        if duration > 0
        else 0
    )

    print(f"  Total Packets     : "
          f"{packets:,}")

    print(f"  Total Bytes       : "
          f"{format_bytes(total_bytes)}")

    print(f"  Packets/sec       : "
          f"{pps:.2f}")



    # ── Protocol Statistics ────────────────────

    protocol_stats = summary.get(
        "protocol_stats", {}
    )

    if protocol_stats:

        print(f"\n{Color.CYAN}"
              f"{'─' * w}"
              f"{Color.RESET}")

        print(f"  {Color.BOLD}"
              f"PROTOCOL STATISTICS"
              f"{Color.RESET}")

        print(f"{Color.CYAN}"
              f"{'─' * w}"
              f"{Color.RESET}")

        total = sum(
            protocol_stats.values()
        )

        # Sort by count descending

        sorted_protocols = sorted(
            protocol_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )

        for proto, count in sorted_protocols:

            pct = (
                (count / total * 100)
                if total > 0
                else 0
            )

            print(
                f"  {proto:18}: "
                f"{count:>8,}   "
                f"({pct:5.2f}%)"
            )



    # ── Risk Statistics ────────────────────────

    risk_stats = summary.get(
        "risk_stats", {}
    )

    if any(risk_stats.values()):

        print(f"\n{Color.CYAN}"
              f"{'─' * w}"
              f"{Color.RESET}")

        print(f"  {Color.BOLD}"
              f"RISK STATISTICS"
              f"{Color.RESET}")

        print(f"{Color.CYAN}"
              f"{'─' * w}"
              f"{Color.RESET}")

        for level in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ]:
            count = risk_stats.get(level, 0)

            if count > 0:

                s_color = severity_color(level)

                print(
                    f"  {s_color}"
                    f"{level:18}"
                    f"{Color.RESET}"
                    f": {count}"
                )



    # ── Attack Statistics ──────────────────────

    print(f"\n{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")

    print(f"  {Color.BOLD}"
          f"ATTACK STATISTICS"
          f"{Color.RESET}")

    print(f"{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")

    print(f"  Total Alerts      : "
          f"{summary.get('alerts', 0)}")

    print(f"  Unique Types      : "
          f"{summary.get('unique_attacks', 0)}")

    # Attack type breakdown

    attack_types = summary.get(
        "attack_types", {}
    )

    if attack_types:

        print()

        for atype, count in sorted(
            attack_types.items(),
            key=lambda x: x[1],
            reverse=True
        ):

            print(
                f"  {Color.DIM}•{Color.RESET} "
                f"{atype:28}: {count}"
            )





# ==========================================================
# Attack History Table
# ==========================================================


def display_attack_history(attacks):
    """
    Display a formatted attack history table.

    Args:
        attacks: List of attack summary dicts.
    """

    w = 65


    print(f"\n{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")

    print(f"  {Color.BOLD}"
          f"ATTACK HISTORY"
          f"{Color.RESET}")

    print(f"{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")


    if not attacks:

        print(f"\n  {Color.GREEN}"
              f"No attacks detected during "
              f"this session."
              f"{Color.RESET}")
        return


    # Table header

    print(f"\n  {Color.BOLD}"
          f"{'ID':<8}"
          f"{'Type':<20}"
          f"{'Severity':<10}"
          f"{'Pkts':<7}"
          f"{'Duration':<10}"
          f"{Color.RESET}")

    print(f"  {'─' * 8}"
          f"{'─' * 20}"
          f"{'─' * 10}"
          f"{'─' * 7}"
          f"{'─' * 10}")


    # Table rows

    for attack in attacks:

        alert_id = str(
            attack.get("alert_id", "?")
        )

        attack_type = str(
            attack.get("attack_type", "?")
        )[:19]

        severity = attack.get(
            "severity", "LOW"
        )

        packets = attack.get(
            "packet_count",
            attack.get("packets", 0)
        )

        duration = attack.get(
            "duration", 0
        )

        s_color = severity_color(severity)

        print(
            f"  {alert_id:<8}"
            f"{attack_type:<20}"
            f"{s_color}"
            f"{severity:<10}"
            f"{Color.RESET}"
            f"{packets:<7}"
            f"{format_duration(duration):<10}"
        )


    # Start/End times below table

    print()

    for attack in attacks:

        alert_id = attack.get(
            "alert_id", "?"
        )

        start = format_time(
            attack.get("start_time")
        )

        end = format_time(
            attack.get("end_time")
        )

        print(
            f"  {Color.DIM}"
            f"{alert_id}: "
            f"{start} → {end}"
            f"{Color.RESET}"
        )





# ==========================================================
# Top Hosts
# ==========================================================


def display_top_hosts(hosts):
    """
    Display top communicating hosts.

    Args:
        hosts: List of (ip, packet_count) tuples.
    """

    w = 65


    print(f"\n{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")

    print(f"  {Color.BOLD}"
          f"TOP COMMUNICATING HOSTS"
          f"{Color.RESET}")

    print(f"{Color.CYAN}"
          f"{'─' * w}"
          f"{Color.RESET}")


    if not hosts:

        print(f"  No host data available.")
        return


    for rank, (ip, count) in enumerate(
        hosts, start=1
    ):

        print(
            f"  {rank:>3}. "
            f"{ip:<22}: "
            f"{count:>8,} packets"
        )





# ==========================================================
# Session Status
# ==========================================================


def display_session_status(summary):
    """
    Display overall session status and DB save status.

    Args:
        summary: Session summary dictionary.
    """

    w = 65
    alerts = summary.get("alerts", 0)


    if alerts == 0:
        status = "CLEAN"
        status_color = Color.GREEN

    elif alerts <= 3:
        status = "SUSPICIOUS"
        status_color = Color.YELLOW

    else:
        status = "UNDER ATTACK"
        status_color = Color.RED


    print(f"\n{Color.CYAN}"
          f"{'═' * w}"
          f"{Color.RESET}")

    print(f"  Session Status    : "
          f"{status_color}{Color.BOLD}"
          f"{status}"
          f"{Color.RESET}")





# ==========================================================
# Database Save Status
# ==========================================================


def display_db_status(success=True):
    """
    Display database save status.

    Args:
        success: True if save succeeded.
    """

    w = 65

    if success:

        print(f"  Database          : "
              f"{Color.GREEN}✓ Saved "
              f"Successfully{Color.RESET}")

    else:

        print(f"  Database          : "
              f"{Color.RED}✗ Save "
              f"Failed{Color.RESET}")


    print(f"\n{Color.CYAN}"
          f"{'═' * w}"
          f"{Color.RESET}\n")
