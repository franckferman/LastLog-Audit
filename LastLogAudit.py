#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
LastLog Audit Tool.

Analyze /var/log/lastlog for system login activities, with flexible output and export options.
"""


import argparse
import csv
from datetime import datetime
import os
import pwd
import struct
from dataclasses import dataclass
from typing import List, Optional, Union



@dataclass
class LastlogRecord:
    username: Optional[str]
    terminal: str
    hostname: str
    login_time: str



BANNER = r"""
    __               __  __                   ___             ___ __
   / /   ____ ______/ /_/ /   ____  ____ _   /   | __  ______/ (_) /_
  / /   / __ `/ ___/ __/ /   / __ \/ __ `/  / /| |/ / / / __  / / __/
 / /___/ /_/ (__  ) /_/ /___/ /_/ / /_/ /  / ___ / /_/ / /_/ / / /_
/_____/\__,_/____/\__/_____/\____/\__, /  /_/  |_\__,_/\__,_/_/\__/
                                 /____/
"""


def show_banner() -> None:
    """Prints the program banner."""
    print(BANNER)


def get_username(uid: int) -> Optional[str]:
    """Returns username for given UID, or None if not found."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def parse_lastlog(filepath: str, include_username: bool) -> List[LastlogRecord]:
    """Parses the lastlog binary file and extracts login records."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[ERROR] File '{filepath}' does not exist.")

    records: List[LastlogRecord] = []
    format_str = "I32s256s"
    record_size = struct.calcsize(format_str)
    structure = struct.Struct(format_str)

    with open(filepath, 'rb') as file:
        uid = 0
        while record := file.read(record_size):
            timestamp, terminal, hostname = structure.unpack(record)
            if timestamp:
                username = get_username(uid) if include_username else None
                terminal = terminal.rstrip(b'\x00').decode('utf-8')
                hostname = hostname.rstrip(b'\x00').decode('utf-8')
                login_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                records.append(LastlogRecord(username, terminal, hostname, login_time))
            uid += 1
    return records


def display_records(records: List[LastlogRecord], mode: str, include_username: bool) -> None:
    """Displays records in the chosen format."""
    header = ["Username", "Terminal", "From", "Last login"] if include_username else ["Terminal", "From", "Last login"]
    col_width = 18

    if mode == 'table':
        print("".join(f"{h:<{col_width}}" for h in header))
        print("-" * (col_width * len(header)))

    for record in records:
        line = [
            record.username if include_username else None,
            record.terminal,
            record.hostname,
            record.login_time
        ]
        line = [item for item in line if item is not None]  # Clean None if username excluded
        if mode == 'table':
            print("".join(f"{item:<{col_width}}" for item in line))
        else:  # 'line'
            print(", ".join(line))


def export_records(records: List[LastlogRecord], filepath: str, format: str, include_username: bool) -> None:
    """Exports records to CSV or TXT file."""
    header = ["Username", "Terminal", "From", "Last login"] if include_username else ["Terminal", "From", "Last login"]

    with open(filepath, 'w', newline='') as file:
        if format == 'csv':
            writer = csv.writer(file)
            writer.writerow(header)
            for record in records:
                row = [record.username, record.terminal, record.hostname, record.login_time] if include_username else [record.terminal, record.hostname, record.login_time]
                writer.writerow(row)
        elif format == 'txt':
            col_width = 18
            file.write("".join(f"{h:<{col_width}}" for h in header) + "\n")
            file.write("-" * (col_width * len(header)) + "\n")
            for record in records:
                line = [
                    record.username if include_username else None,
                    record.terminal,
                    record.hostname,
                    record.login_time
                ]
                line = [item for item in line if item is not None]
                file.write("".join(f"{item:<{col_width}}" for item in line) + "\n")


def parse_args() -> argparse.Namespace:
    """Parses CLI arguments."""
    parser = argparse.ArgumentParser(description="Analyze /var/log/lastlog for login activity.")
    parser.add_argument('--file', default='/var/log/lastlog', help="Path to lastlog file (default: /var/log/lastlog).")
    parser.add_argument('--display', choices=['table', 'line'], default='table', help="Output format (default: table).")
    parser.add_argument('--include-username', action='store_true', help="Include usernames (accurate on local system).")
    parser.add_argument('--export', help="Export output to file (requires --export-format).")
    parser.add_argument('--export-format', choices=['csv', 'txt'], default='txt', help="Export format (csv/txt).")
    return parser.parse_args()


def main() -> None:
    """Main entrypoint."""
    show_banner()
    args = parse_args()

    try:
        records = parse_lastlog(args.file, args.include_username)
        if not records:
            print("[INFO] No login records found.")
            return

        if args.export:
            export_records(records, args.export, args.export_format, args.include_username)
            print(f"[+] Data exported to {args.export}")
        else:
            display_records(records, args.display, args.include_username)
    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()

