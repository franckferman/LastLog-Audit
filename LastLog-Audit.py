#!/usr/bin/env python3
"""
LastLog Audit Tool.

Analyzes /var/log/lastlog for system login activities to assist in security audits and compliance. 
Features include custom output formats and an option to include usernames. Suitable for system 
administrators and security professionals.

Author: Franck FERMAN @franckferman
Date: 04/04/24
Version: 1.0.0
"""

import argparse
import csv
from datetime import datetime
import pwd
import struct
from typing import List, Tuple, Union


BANNER = r"""
    __               __  __                   ___             ___ __ 
   / /   ____ ______/ /_/ /   ____  ____ _   /   | __  ______/ (_) /_
  / /   / __ `/ ___/ __/ /   / __ \/ __ `/  / /| |/ / / / __  / / __/
 / /___/ /_/ (__  ) /_/ /___/ /_/ / /_/ /  / ___ / /_/ / /_/ / / /_  
/_____/\__,_/____/\__/_____/\____/\__, /  /_/  |_\__,_/\__,_/_/\__/  
                                 /____/                              
"""


def show_banner() -> None:
    """Print the banner."""
    print(BANNER)


def get_username(uid: int) -> Union[str, None]:
    """
    Retrieves the username associated with a given user ID (UID).

    This function looks up the system's user database to find a username corresponding
    to the provided UID. If the UID exists in the database, the username is returned.
    If there is no entry for the UID, the function returns None, indicating that
    the UID is not associated with any user on the system.

    Args:
        uid: The user ID for which to find the corresponding username.

    Returns:
        The username as a string if found, otherwise None.
    """
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def collect_lastlog_data(filepath: str, include_username: bool) -> List[Union[Tuple[str, str, str, str], Tuple[str, str, str]]]:
    """
    Extracts and formats login activity records from a specified lastlog file.

    Parses binary lastlog data to collect timestamp, terminal, and hostname information.
    Optionally includes associated usernames. Each record is returned as a tuple within
    a list of all records found. Handles file reading and binary data unpacking.

    Args:
        filepath: Path to the lastlog file.
        include_username: Flag to include the username in each record.

    Returns:
        A list of tuples containing record details. Each tuple contains either three elements
        (terminal, hostname, login time) if include_username is False, or four elements
        (username, terminal, hostname, login time) if include_username is True.

    Raises:
        Exception: Generic exception if file reading or data unpacking fails.
    """
    data = []
    format_str = "I32s256s"  # Define the unpacking format for struct.
    record_size = struct.calcsize(format_str)  # Calculate size of each record.
    structure = struct.Struct(format_str)  # Compile the structure format.

    try:
        with open(filepath, 'rb') as file:
            uid = 0
            while True:
                record_data = file.read(record_size)  # Read a record's worth of data.
                if not record_data:
                    break  # Exit loop if no more data is read.
                timestamp, terminal, hostname = structure.unpack(record_data)  # Unpack data.
                if timestamp:  # Check if timestamp is valid (non-zero).
                    username = get_username(uid) if include_username else ''
                    terminal = terminal.rstrip(b'\x00').decode('utf-8')
                    hostname = hostname.rstrip(b'\x00').decode('utf-8')
                    login_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    record = (username, terminal, hostname, login_time) if include_username else (terminal, hostname, login_time)
                    data.append(record)
                uid += 1
    except Exception as e:
        print(f"An error occurred: {e}")
    return data


def display_data(data: List[Union[Tuple[str, str, str, str], Tuple[str, str, str]]], display_mode: str, include_username: bool) -> None:
    """
    Displays login activity records in a specified format.

    Formats and prints a list of login activity records to the console, either in a
    tabular format or as a series of lines. The tabular format includes headers, and both
    formats are adjustable to include or exclude usernames.

    Args:
        data: A list of tuples, each containing login record details. Each tuple
              contains either terminal, hostname, and login time, or username,
              terminal, hostname, and login time, depending on the include_username flag.
        display_mode: Specifies the display format, either 'table' for tabular output
                      or 'line' for line-separated output.
        include_username: Flag indicating whether to include the username in the output.

    No return value, as this function solely prints to the console.
    """
    if display_mode == 'table':
        header = ['Username', 'Terminal', 'From', 'Latest'] if include_username else ['Terminal', 'From', 'Latest']
        print(" ".join(f"{item:<15}" for item in header))
        print("-" * (15 * len(header)))

    for record in data:
        if display_mode == 'line':
            print(", ".join(record))
        elif display_mode == 'table':
            print(" ".join(f"{item:<15}" for item in record))



def export_data(data: List[Union[Tuple[str, str, str, str], Tuple[str, str, str]]], filepath: str, display_mode: str, include_username: bool, export_format: str) -> None:
    """
    Exports collected login data to a file in either CSV or TXT format.

    This function writes the login activity records to a specified file, allowing
    for the choice between CSV and TXT formats. In CSV format, data is comma-separated
    with a header row. In TXT format, data can be presented in a table or line-by-line,
    with optional inclusion of headers.

    Args:
        data: A list of tuples containing the login record details. Each tuple has
              either three elements (terminal, hostname, login time) or four elements
              (username, terminal, hostname, login time), depending on the
              include_username flag.
        filepath: The path to the output file where data will be written.
        display_mode: Determines the format of the TXT output ('table' or 'line').
                      This argument is ignored for CSV output.
        include_username: Indicates whether the username should be included in the
                          output. Affects both CSV and TXT formats.
        export_format: Specifies the output format ('csv' or 'txt').

    No return value. This function writes directly to a file specified by the filepath.
    """
    if export_format == 'csv':
        headers = ['Username', 'Terminal', 'From', 'Latest'] if include_username else ['Terminal', 'From', 'Latest']
        with open(filepath, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            for record in data:
                writer.writerow(record)
    elif export_format == 'txt':
        with open(filepath, 'w') as f:
            if display_mode == 'table':
                header = ['Username', 'Terminal', 'From', 'Latest'] if include_username else ['Terminal', 'From', 'Latest']
                f.write(" ".join(f"{item:<15}" for item in header) + "\n")
                f.write("-" * (15 * len(header)) + "\n")
            for record in data:
                if display_mode == 'line':
                    f.write(", ".join(record) + "\n")
                elif display_mode == 'table':
                    f.write(" ".join(f"{item:<15}" for item in record) + "\n")


def parse_arguments():
    """Configures and parses command-line arguments for auditing /var/log/lastlog."""
    parser = argparse.ArgumentParser(
        description="Analyzes /var/log/lastlog to generate login activity reports. Designed for security audits."
    )
    parser.add_argument(
        '--file', 
        default='/var/log/lastlog', 
        help="Specifies the lastlog file path. Defaults to system's '/var/log/lastlog'."
    )
    parser.add_argument(
        '--display', 
        choices=['table', 'line'], 
        default='table', 
        help="Determines the output format: 'table' for tabular and 'line' for line-by-line display. Default: 'table'."
    )
    parser.add_argument(
        '--include-username', 
        action='store_true', 
        help="Includes usernames in output. Accurate only when run on the target system due to UID mapping."
    )
    parser.add_argument(
        '--export', 
        help="Path for exporting the data. If unspecified, outputs to console. Use with --export-format."
    )
    parser.add_argument(
        '--export-format', 
        choices=['txt', 'csv'], 
        default='txt', 
        help="Format for exported data: 'txt' (default) or 'csv'. Requires --export to be set."
    )

    return parser.parse_args()


def main():
    show_banner()

    try:
        args = parse_arguments()
        data = collect_lastlog_data(args.file, args.include_username)
        
        if args.export:
            export_data(data, args.export, args.display, args.include_username, args.export_format)
            print("")
        else:
            display_data(data, args.display, args.include_username)
            print("")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
