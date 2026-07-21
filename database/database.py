"""
====================================================
Network Intrusion Detection System (NIDS)
Module : Database Manager

Description:
Handles SQLite database creation, packet storage,
alert retrieval and log management.
====================================================
"""

import sqlite3

# ==================================================
# Database Configuration
# ==================================================

DATABASE_NAME = "database/nids.db"


# ==================================================
# Create Database and Table
# ==================================================

def create_database():
    """
    Creates the SQLite database and packets table
    if they do not already exist.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            src_ip TEXT,

            dst_ip TEXT,

            protocol TEXT,

            src_port INTEGER,

            dst_port INTEGER,

            packet_size INTEGER,

            status TEXT,

            severity TEXT,

            rule_id TEXT,

            attack TEXT,

            reason TEXT

        )
        """
    )

    connection.commit()

    connection.close()


# ==================================================
# Insert Packet
# ==================================================

def insert_packet(packet_info, result):
    """
    Stores one analyzed packet into the database.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO packets
        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_size,
            status,
            severity,
            rule_id,
            attack,
            reason
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (

            str(packet_info["timestamp"]),

            packet_info["src_ip"],

            packet_info["dst_ip"],

            packet_info["protocol"],

            packet_info["src_port"],

            packet_info["dst_port"],

            packet_info["packet_size"],

            result["status"],

            result["severity"],

            result["rule_id"],

            result["attack"],

            result["reason"]

        )
    )

    connection.commit()

    connection.close()


# ==================================================
# Get All Packets
# ==================================================

def get_packets():
    """
    Returns all packets stored in the database.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT * FROM packets
        ORDER BY id DESC
        """
    )

    packets = cursor.fetchall()

    connection.close()

    return packets


# ==================================================
# Get Only Alerts
# ==================================================

def get_alerts():
    """
    Returns only ALERT packets.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM packets
        WHERE status='ALERT'
        ORDER BY id DESC
        """
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ==================================================
# Clear Database
# ==================================================

def clear_database():
    """
    Deletes all packet records.
    """

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM packets
        """
    )

    connection.commit()

    connection.close()