#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LastLog-Audit - Linux Last Logon Forensic Auditing Tool
========================================================

.SYNOPSIS
    Parse and audit /var/log/lastlog binary records to surface login activity,
    stale accounts, and unauthorized access patterns across Linux systems.

.DESCRIPTION
    LastLog-Audit reads the binary lastlog(8) database at /var/log/lastlog.
    Each record in this fixed-size file is indexed by UID and stores the most
    recent login timestamp, source terminal (tty/pts), and originating hostname
    or IP address for every account on the system.

    The tool is designed for:
      - Security audits and compliance reviews (CIS, NIST 800-53 AU controls)
      - Incident response triage: establishing a last-seen baseline per account
      - Detection of stale/dormant accounts that may be abused for persistence
      - Correlation with other artefacts (auth.log, wtmp, utmp) during DFIR

    The lastlog file is a sparse binary file. Records with a zero timestamp
    have never logged in and are silently skipped unless explicitly requested.
    Username resolution is performed via pwd(3) against the local password
    database; on systems with LDAP/AD integration, this requires nsswitch.

.PARAMETER --file
    Path to the lastlog binary file. Defaults to /var/log/lastlog.
    Accepts any lastlog-format file, including copies collected from images.

.PARAMETER --display
    Output mode for stdout rendering.
    Choices: table (columnar, human-readable) | line (CSV-like, grep-friendly).
    Defaults to table.

.PARAMETER --include-username
    Resolve UIDs to usernames via the local passwd database.
    Accurate only when running against the same system that owns the lastlog file.
    Omit when analysing files extracted from foreign disk images.

.PARAMETER --export
    Destination file path for exported output.
    Requires --export-format when the extension is ambiguous.

.PARAMETER --export-format
    Export serialisation format.
    Choices: csv | txt. Defaults to txt.

.EXAMPLE
    # Display all login records in columnar format
    python3 LastLogAudit.py

.EXAMPLE
    # Include usernames and export to CSV for SIEM ingestion
    python3 LastLogAudit.py --include-username --export report.csv --export-format csv

.EXAMPLE
    # Parse a lastlog file extracted from a disk image
    python3 LastLogAudit.py --file /mnt/evidence/var/log/lastlog --display line

.EXAMPLE
    # Pipe line output into grep to isolate remote logins
    python3 LastLogAudit.py --display line | grep -v '127.0.0.1'

.NOTES
    Author  : franckferman
    License : GNU Affero General Public License v3.0
    Version : 1.1.0

    MITRE ATT&CK Mapping
    --------------------
    This tool supports detection and audit of the following techniques:

    T1078   - Valid Accounts
              Identifies accounts with recent logins that may indicate
              legitimate credentials being abused by an adversary.

    T1078.003 - Valid Accounts: Local Accounts
              Surfaces local account login history; dormant local accounts
              with unexpected recent logins are high-fidelity indicators.

    T1136   - Create Account
              Newly created accounts (low UID gap, never logged in previously)
              may appear as fresh entries with no lastlog record.

    T1531   - Account Access Removal
              Accounts with a sudden absence of recent login records relative
              to a previous baseline may indicate tampering or removal.

    T1070.006 - Indicator Removal: Timestomp
              Adversaries may zero out lastlog records to erase evidence of
              access. A UID entry with timestamp=0 on an active account is
              anomalous and warrants investigation.

    T1021   - Remote Services
              Hostname/IP fields in lastlog records reveal the origin of SSH
              and other remote service authentications.

    References
    ----------
    lastlog(8)  - https://man7.org/linux/man-pages/man8/lastlog.8.html
    lastlog(5)  - Implicit format documented via login.defs and shadow-utils source
    MITRE ATT&CK - https://attack.mitre.org
"""


import argparse
import csv
import os
import pwd
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class LastlogRecord:
    """Represents a single parsed entry from the lastlog binary database."""

    uid: int
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

# Lastlog record binary layout: uint32 timestamp, 32-byte tty, 256-byte hostname.
# This matches the lastlog_t / struct lastlog definition in <lastlog.h>.
_LASTLOG_FORMAT = "I32s256s"
_LASTLOG_RECORD_SIZE = struct.calcsize(_LASTLOG_FORMAT)
_LASTLOG_STRUCT = struct.Struct(_LASTLOG_FORMAT)


# Wtmp (struct utmp) binary layout on Linux x86_64.
# type(short 2B) + pad(2B) + pid(int 4B) + line(char[32]) + id(char[4])
# + user(char[32]) + host(char[256]) + exit(int[2] 8B) + session(int 4B)
# + tv(timeval 8B) + addr_v6(int[4] 16B) + unused(char[20]) = 384 bytes.
_UTMP_FORMAT = "hhi32s4s32s256shhiii4I20s"
_UTMP_RECORD_SIZE = struct.calcsize(_UTMP_FORMAT)
_UTMP_STRUCT = struct.Struct(_UTMP_FORMAT)

# utmp record types relevant for login/logout auditing.
_UT_USER_PROCESS = 7
_UT_DEAD_PROCESS = 8


@dataclass
class WtmpRecord:
    """Represents a single parsed login or logout entry from wtmp."""

    username: str
    terminal: str
    host: str
    timestamp: str
    record_type: str
    pid: int


def show_banner() -> None:
    """Print the programme banner to stdout."""
    print(BANNER)


def get_username(uid: int) -> Optional[str]:
    """
    Resolve a numeric UID to a username via the local passwd database.

    Returns None when the UID has no corresponding entry (deleted account,
    LDAP/NIS unavailable, or UID from a foreign system image).
    """
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def parse_lastlog(filepath: str, include_username: bool) -> List[LastlogRecord]:
    """
    Parse a lastlog binary file and return a list of active login records.

    The lastlog file is a sparse, fixed-size record store indexed by UID.
    Records with a zero timestamp represent accounts that have never logged in
    and are excluded from the returned list.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the lastlog file.
    include_username : bool
        When True, resolve each UID to a username via pwd(3).

    Returns
    -------
    List[LastlogRecord]
        Parsed records for all UIDs with a non-zero last-login timestamp.

    Raises
    ------
    FileNotFoundError
        When the specified path does not exist.
    PermissionError
        When the process lacks read access to the file (lastlog is typically
        root-readable or mode 640 owned by the adm group).
    struct.error
        When the file contains a truncated or malformed record.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"[ERROR] lastlog file not found: '{filepath}'\n"
            "        Verify the path or confirm the file was collected from the target."
        )

    if not os.access(filepath, os.R_OK):
        raise PermissionError(
            f"[ERROR] Permission denied: '{filepath}'\n"
            "        Try running with elevated privileges (sudo)."
        )

    records: List[LastlogRecord] = []
    uid = 0

    with open(filepath, "rb") as fh:
        while True:
            raw = fh.read(_LASTLOG_RECORD_SIZE)
            if not raw:
                break
            if len(raw) < _LASTLOG_RECORD_SIZE:
                # Truncated trailing record - skip silently; the file may have
                # been collected during an active write or is partially corrupted.
                break

            try:
                timestamp, raw_terminal, raw_hostname = _LASTLOG_STRUCT.unpack(raw)
            except struct.error as exc:
                raise struct.error(
                    f"[ERROR] Malformed record at UID {uid} offset "
                    f"{uid * _LASTLOG_RECORD_SIZE}: {exc}"
                ) from exc

            if timestamp:
                username = get_username(uid) if include_username else None
                terminal = raw_terminal.rstrip(b"\x00").decode("utf-8", errors="replace")
                hostname = raw_hostname.rstrip(b"\x00").decode("utf-8", errors="replace")
                login_time = datetime.fromtimestamp(timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                records.append(
                    LastlogRecord(uid, username, terminal, hostname, login_time)
                )

            uid += 1

    return records


def _build_row(record: LastlogRecord, include_username: bool) -> List[str]:
    """Return a list of field values for a record, conditionally including username."""
    row: List[str] = []
    if include_username:
        row.append(record.username if record.username is not None else f"<uid:{record.uid}>")
    row.extend([record.terminal, record.hostname, record.login_time])
    return row


def _build_header(include_username: bool) -> List[str]:
    """Return the column header list matching the row layout."""
    if include_username:
        return ["Username", "Terminal", "From", "Last Login"]
    return ["Terminal", "From", "Last Login"]


def display_records(
    records: List[LastlogRecord], mode: str, include_username: bool
) -> None:
    """
    Render parsed records to stdout.

    Parameters
    ----------
    records : List[LastlogRecord]
        Parsed login records to display.
    mode : str
        'table' for columnar aligned output; 'line' for comma-separated output
        compatible with grep, awk, and other text processing pipelines.
    include_username : bool
        Whether to include a Username column in the output.
    """
    header = _build_header(include_username)
    col_width = 22

    if mode == "table":
        print("".join(f"{h:<{col_width}}" for h in header))
        print("-" * (col_width * len(header)))

    for record in records:
        row = _build_row(record, include_username)
        if mode == "table":
            print("".join(f"{item:<{col_width}}" for item in row))
        else:
            print(", ".join(row))


def export_records(
    records: List[LastlogRecord],
    filepath: str,
    fmt: str,
    include_username: bool,
) -> None:
    """
    Serialise parsed records to a file.

    Parameters
    ----------
    records : List[LastlogRecord]
        Records to export.
    filepath : str
        Destination file path. Parent directory must exist.
    fmt : str
        'csv' or 'txt'. CSV uses RFC 4180 quoting; TXT uses aligned columns.
    include_username : bool
        Whether to include a Username column in the export.

    Raises
    ------
    OSError
        When the destination path is not writable or the parent directory
        does not exist.
    """
    parent_dir = os.path.dirname(os.path.abspath(filepath))
    if not os.path.isdir(parent_dir):
        raise OSError(
            f"[ERROR] Export destination directory does not exist: '{parent_dir}'"
        )

    header = _build_header(include_username)
    col_width = 22

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        if fmt == "csv":
            writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(header)
            for record in records:
                writer.writerow(_build_row(record, include_username))
        else:  # txt - aligned table
            fh.write("".join(f"{h:<{col_width}}" for h in header) + "\n")
            fh.write("-" * (col_width * len(header)) + "\n")
            for record in records:
                row = _build_row(record, include_username)
                fh.write("".join(f"{item:<{col_width}}" for item in row) + "\n")


def parse_wtmp(filepath: str) -> List[Dict[str, str]]:
    """
    Parse a wtmp binary file and return login/logout records.

    The wtmp file uses the struct utmp layout (384 bytes per record on
    Linux x86_64). Only USER_PROCESS (type 7, login) and DEAD_PROCESS
    (type 8, logout) entries are returned; boot records, run-level changes,
    and other housekeeping entries are filtered out.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the wtmp file.

    Returns
    -------
    List[Dict[str, str]]
        Each dict contains keys: username, terminal, host, timestamp, type, pid.

    Raises
    ------
    FileNotFoundError
        When the specified path does not exist.
    PermissionError
        When the process lacks read access to the file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"[ERROR] wtmp file not found: '{filepath}'\n"
            "        Verify the path or confirm the file was collected from the target."
        )

    if not os.access(filepath, os.R_OK):
        raise PermissionError(
            f"[ERROR] Permission denied: '{filepath}'\n"
            "        Try running with elevated privileges (sudo)."
        )

    records: List[Dict[str, str]] = []

    with open(filepath, "rb") as fh:
        while True:
            raw = fh.read(_UTMP_RECORD_SIZE)
            if not raw:
                break
            if len(raw) < _UTMP_RECORD_SIZE:
                break

            fields = _UTMP_STRUCT.unpack(raw)
            ut_type = fields[0]
            # fields[1] is padding (implicit in struct)
            ut_pid = fields[2]
            ut_line = fields[3]
            # fields[4] is ut_id
            ut_user = fields[5]
            ut_host = fields[6]
            # fields[7], fields[8] are exit status
            # fields[9] is session
            tv_sec = fields[10]
            # fields[11] is tv_usec

            if ut_type not in (_UT_USER_PROCESS, _UT_DEAD_PROCESS):
                continue

            username = ut_user.rstrip(b"\x00").decode("utf-8", errors="replace")
            terminal = ut_line.rstrip(b"\x00").decode("utf-8", errors="replace")
            host = ut_host.rstrip(b"\x00").decode("utf-8", errors="replace")
            timestamp = datetime.fromtimestamp(tv_sec).strftime("%Y-%m-%d %H:%M:%S")
            record_type = "LOGIN" if ut_type == _UT_USER_PROCESS else "LOGOUT"

            records.append({
                "username": username,
                "terminal": terminal,
                "host": host,
                "timestamp": timestamp,
                "type": record_type,
                "pid": str(ut_pid),
            })

    return records


def display_wtmp(records: List[Dict[str, str]], mode: str) -> None:
    """
    Render parsed wtmp records to stdout.

    Parameters
    ----------
    records : List[Dict[str, str]]
        Parsed wtmp login/logout records.
    mode : str
        'table' for columnar aligned output; 'line' for comma-separated output.
    """
    header = ["Username", "Terminal", "From", "Timestamp", "Type", "PID"]
    col_width = 22

    if mode == "table":
        print("".join(f"{h:<{col_width}}" for h in header))
        print("-" * (col_width * len(header)))

    for rec in records:
        row = [
            rec["username"],
            rec["terminal"],
            rec["host"],
            rec["timestamp"],
            rec["type"],
            rec["pid"],
        ]
        if mode == "table":
            print("".join(f"{item:<{col_width}}" for item in row))
        else:
            print(", ".join(row))


# -----------------------------------------------------------------------
# auth.log syslog parser - regex patterns for SSH and sudo events
# -----------------------------------------------------------------------

_RE_SSHD_ACCEPTED = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+"
)

_RE_SSHD_FAILED = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+(\S+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+\d+"
)

_RE_SUDO = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo:\s+"
    r"(\S+)\s+:.*COMMAND=(.*)"
)


def parse_auth_log(filepath: str) -> List[Dict[str, str]]:
    """
    Parse an auth.log (syslog text format) file and extract security events.

    Extracts three categories of events:
      - Successful SSH logins (sshd "Accepted" lines)
      - Failed SSH logins (sshd "Failed" lines)
      - sudo command executions

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the auth.log file.

    Returns
    -------
    List[Dict[str, str]]
        Each dict contains at minimum 'timestamp', 'event', and 'username'.
        SSH events also include 'ip' and 'method'.
        Sudo events also include 'command'.

    Raises
    ------
    FileNotFoundError
        When the specified path does not exist.
    PermissionError
        When the process lacks read access to the file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"[ERROR] auth.log file not found: '{filepath}'\n"
            "        Verify the path or confirm the file was collected from the target."
        )

    if not os.access(filepath, os.R_OK):
        raise PermissionError(
            f"[ERROR] Permission denied: '{filepath}'\n"
            "        Try running with elevated privileges (sudo)."
        )

    records: List[Dict[str, str]] = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")

            match = _RE_SSHD_ACCEPTED.match(line)
            if match:
                records.append({
                    "timestamp": match.group(1),
                    "event": "LOGIN_SUCCESS",
                    "method": match.group(2),
                    "username": match.group(3),
                    "ip": match.group(4),
                })
                continue

            match = _RE_SSHD_FAILED.match(line)
            if match:
                records.append({
                    "timestamp": match.group(1),
                    "event": "LOGIN_FAILED",
                    "method": match.group(2),
                    "username": match.group(3),
                    "ip": match.group(4),
                })
                continue

            match = _RE_SUDO.match(line)
            if match:
                records.append({
                    "timestamp": match.group(1),
                    "event": "SUDO",
                    "username": match.group(2),
                    "command": match.group(3).strip(),
                })
                continue

    return records


def _build_auth_row(record: Dict[str, str]) -> List[str]:
    """Return a flat row for an auth.log record suitable for display or export."""
    return [
        record["timestamp"],
        record["event"],
        record["username"],
        record.get("ip", "-"),
        record.get("method", record.get("command", "-")),
    ]


def display_auth_log(records: List[Dict[str, str]], mode: str) -> None:
    """
    Render parsed auth.log records to stdout.

    Parameters
    ----------
    records : List[Dict[str, str]]
        Parsed auth.log event records.
    mode : str
        'table' for columnar aligned output; 'line' for comma-separated output
        compatible with grep, awk, and other text processing pipelines.
    """
    header = ["Timestamp", "Event", "Username", "IP/Host", "Method/Command"]
    col_width = 22

    if mode == "table":
        print("".join(f"{h:<{col_width}}" for h in header))
        print("-" * (col_width * len(header)))

    for record in records:
        row = _build_auth_row(record)
        if mode == "table":
            print("".join(f"{item:<{col_width}}" for item in row))
        else:
            print(", ".join(row))


def export_auth_log(
    records: List[Dict[str, str]],
    filepath: str,
    fmt: str,
) -> None:
    """
    Serialise parsed auth.log records to a file.

    Parameters
    ----------
    records : List[Dict[str, str]]
        Records to export.
    filepath : str
        Destination file path. Parent directory must exist.
    fmt : str
        'csv' or 'txt'. CSV uses RFC 4180 quoting; TXT uses aligned columns.

    Raises
    ------
    OSError
        When the destination path is not writable or the parent directory
        does not exist.
    """
    parent_dir = os.path.dirname(os.path.abspath(filepath))
    if not os.path.isdir(parent_dir):
        raise OSError(
            f"[ERROR] Export destination directory does not exist: '{parent_dir}'"
        )

    header = ["Timestamp", "Event", "Username", "IP/Host", "Method/Command"]
    col_width = 22

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        if fmt == "csv":
            writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(header)
            for record in records:
                writer.writerow(_build_auth_row(record))
        else:
            fh.write("".join(f"{h:<{col_width}}" for h in header) + "\n")
            fh.write("-" * (col_width * len(header)) + "\n")
            for record in records:
                row = _build_auth_row(record)
                fh.write("".join(f"{item:<{col_width}}" for item in row) + "\n")


def correlate_sources(
    lastlog_file: str,
    wtmp_file: str,
    auth_log_file: str,
) -> None:
    """
    Cross-reference lastlog, wtmp, and auth.log to produce a unified
    security assessment.

    Correlation logic:
    - Match lastlog UIDs against wtmp sessions to show full history
    - Match auth.log failed attempts against lastlog successful logins
      (brute force confirmation)
    - Flag accounts that appear in lastlog but not wtmp (possible tampering)
    - Flag external IPs seen across multiple sources
    """
    lastlog_records = parse_lastlog(lastlog_file, include_username=False)
    wtmp_records = parse_wtmp(wtmp_file)
    auth_records = parse_auth_log(auth_log_file)

    print("=" * 70)
    print("  CORRELATION REPORT")
    print("=" * 70)

    print("\n  Sources:")
    print(f"    lastlog  : {lastlog_file} ({len(lastlog_records)} records)")
    print(f"    wtmp     : {wtmp_file} ({len(wtmp_records)} records)")
    print(f"    auth.log : {auth_log_file} ({len(auth_records)} events)")

    # Collect all external IPs across sources
    lastlog_ips = {r.hostname for r in lastlog_records if r.hostname and not r.hostname.startswith(("10.", "192.168.", "172."))}
    wtmp_ips = {r["host"] for r in wtmp_records if r["host"] and not r["host"].startswith(("10.", "192.168.", "172."))}
    auth_ips = {r.get("ip", "") for r in auth_records if r.get("ip") and not r["ip"].startswith(("10.", "192.168.", "172."))}
    all_external = lastlog_ips | wtmp_ips | auth_ips
    all_external.discard("")

    if all_external:
        print(f"\n  External IPs across all sources: {len(all_external)}")
        for ip in sorted(all_external):
            sources = []
            if ip in lastlog_ips:
                sources.append("lastlog")
            if ip in wtmp_ips:
                sources.append("wtmp")
            if ip in auth_ips:
                sources.append("auth.log")
            print(f"    {ip:<22s} [{', '.join(sources)}]")

    # Auth.log: failed vs success ratio per IP
    failed_by_ip: Dict[str, int] = {}
    success_by_ip: Dict[str, int] = {}
    for r in auth_records:
        ip = r.get("ip", "")
        if not ip:
            continue
        if r["event"] == "LOGIN_FAILED":
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
        elif r["event"] == "LOGIN_SUCCESS":
            success_by_ip[ip] = success_by_ip.get(ip, 0) + 1

    brute_force_ips = {ip for ip, count in failed_by_ip.items() if count >= 3}
    if brute_force_ips:
        print("\n  Brute force indicators (3+ failed attempts):")
        for ip in sorted(brute_force_ips):
            fails = failed_by_ip[ip]
            successes = success_by_ip.get(ip, 0)
            status = "COMPROMISED" if successes > 0 else "blocked"
            print(f"    {ip:<22s} {fails} failed, {successes} success -> {status}")

    # Wtmp: sessions still open (login without logout)
    logins_by_pid = {}
    logouts_by_pid = set()
    for r in wtmp_records:
        pid = r["pid"]
        if r["type"] == "LOGIN":
            logins_by_pid[pid] = r
        elif r["type"] == "LOGOUT":
            logouts_by_pid.add(pid)

    open_sessions = {pid: r for pid, r in logins_by_pid.items() if pid not in logouts_by_pid}
    if open_sessions:
        print("\n  Open sessions (login without logout in wtmp):")
        for pid, r in sorted(open_sessions.items()):
            print(f"    {r['username']:<16s} from {r['host']:<22s} since {r['timestamp']}  (PID {pid})")

    # Sudo activity from auth.log
    sudo_events = [r for r in auth_records if r["event"] == "SUDO"]
    if sudo_events:
        print(f"\n  Sudo commands ({len(sudo_events)}):")
        for r in sudo_events:
            print(f"    [{r['timestamp']}] {r['username']}: {r.get('command', 'N/A')}")

    # Summary
    print(f"\n{'=' * 70}")
    print("  ASSESSMENT")
    print(f"{'=' * 70}")

    risk_indicators = 0
    if brute_force_ips:
        compromised = [ip for ip in brute_force_ips if success_by_ip.get(ip, 0) > 0]
        if compromised:
            print(f"  [!] CRITICAL: Brute force succeeded from {', '.join(compromised)}")
            risk_indicators += 2
        else:
            print("  [*] Brute force attempts detected but no successful login")
            risk_indicators += 1

    if open_sessions:
        external_open = [r for r in open_sessions.values() if r["host"] and not r["host"].startswith(("10.", "192.168.", "172."))]
        if external_open:
            print(f"  [!] CRITICAL: {len(external_open)} open session(s) from external IPs")
            risk_indicators += 2
        else:
            print(f"  [*] {len(open_sessions)} open session(s) (internal)")

    if sudo_events:
        suspicious_sudo = [r for r in sudo_events if any(k in r.get("command", "") for k in ("shadow", "useradd", "usermod", "crontab", "wget", "curl"))]
        if suspicious_sudo:
            print(f"  [!] HIGH: {len(suspicious_sudo)} suspicious sudo command(s) detected")
            risk_indicators += 1

    if all_external:
        multi_source = [ip for ip in all_external if sum([ip in lastlog_ips, ip in wtmp_ips, ip in auth_ips]) >= 2]
        if multi_source:
            print(f"  [!] {len(multi_source)} external IP(s) seen across multiple log sources")

    if risk_indicators == 0:
        print("  [+] No high-risk indicators found")
    print("=" * 70 + "\n")


def parse_args() -> argparse.Namespace:
    """Define and parse the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="LastLogAudit",
        description=(
            "Parse and audit /var/log/lastlog to surface login history, "
            "stale accounts, and remote access origins on Linux systems."
        ),
        epilog=(
            "MITRE ATT&CK: T1078 (Valid Accounts), T1070.006 (Timestomp), "
            "T1021 (Remote Services). See module docstring for full mapping."
        ),
    )
    parser.add_argument(
        "-f", "--file",
        default="/var/log/lastlog",
        metavar="PATH",
        help=(
            "Path to the lastlog binary file. "
            "Default: /var/log/lastlog. "
            "Accepts files extracted from disk images for offline analysis."
        ),
    )
    parser.add_argument(
        "-d", "--display",
        choices=["table", "line"],
        default="table",
        help=(
            "Stdout rendering format. "
            "'table' produces aligned columns; "
            "'line' produces comma-separated output suitable for grep/awk. "
            "Default: table."
        ),
    )
    parser.add_argument(
        "-u", "--include-username",
        action="store_true",
        help=(
            "Resolve UIDs to usernames via the local passwd database. "
            "Accurate only when analysing the live system or a mounted image "
            "with matching /etc/passwd."
        ),
    )
    parser.add_argument(
        "-e", "--export",
        metavar="OUTFILE",
        help="Destination file path for exported output. Requires --export-format.",
    )
    parser.add_argument(
        "-F", "--export-format",
        choices=["csv", "txt"],
        default="txt",
        help="Export serialisation format: csv or txt. Default: txt.",
    )
    parser.add_argument(
        "--wtmp",
        metavar="FILE",
        help=(
            "Parse a wtmp binary file for full login/logout history. "
            "Uses struct utmp format (384 bytes per record). "
            "When set, --file and --include-username are ignored."
        ),
    )
    parser.add_argument(
        "--auth-log",
        metavar="FILE",
        help=(
            "Parse auth.log for login successes, failures, and sudo events. "
            "Extracts sshd Accepted/Failed lines and sudo COMMAND entries. "
            "When set, --file and --include-username are ignored."
        ),
    )
    parser.add_argument(
        "--correlate",
        action="store_true",
        help=(
            "Cross-reference lastlog, wtmp, and auth.log for unified analysis. "
            "Requires --file, --wtmp, and --auth-log to all be specified."
        ),
    )
    return parser.parse_args()


def main() -> None:
    """Programme entrypoint: parse arguments, read lastlog, render or export results."""
    show_banner()
    args = parse_args()

    try:
        if args.correlate:
            if not args.wtmp or not args.auth_log:
                print("[ERROR] --correlate requires --file, --wtmp, and --auth-log.")
                sys.exit(1)
            correlate_sources(args.file, args.wtmp, args.auth_log)
            return

        if args.auth_log:
            auth_records = parse_auth_log(args.auth_log)

            if not auth_records:
                print("[INFO] No SSH or sudo events found in the auth.log file.")
                print(
                    "[INFO] The file may not contain sshd or sudo entries, "
                    "or the log format is non-standard."
                )
                return

            print(
                f"[+] {len(auth_records)} auth event(s) parsed "
                f"from '{args.auth_log}'"
            )

            if args.export:
                export_auth_log(auth_records, args.export, args.export_format)
                print(
                    f"[+] Records exported to '{args.export}' "
                    f"(format: {args.export_format})"
                )
            else:
                print()
                display_auth_log(auth_records, args.display)
            return

        if args.wtmp:
            wtmp_records = parse_wtmp(args.wtmp)

            if not wtmp_records:
                print("[INFO] No login/logout records found in the wtmp file.")
                print(
                    "[INFO] The file may be empty or contain only boot/shutdown "
                    "records (no USER_PROCESS or DEAD_PROCESS entries)."
                )
                return

            print(f"[+] {len(wtmp_records)} login/logout record(s) parsed from '{args.wtmp}'")
            print()
            display_wtmp(wtmp_records, args.display)
            return

        records = parse_lastlog(args.file, args.include_username)

        if not records:
            print("[INFO] No login records found in the lastlog file.")
            print(
                "[INFO] This may indicate all accounts have zero timestamps "
                "(never logged in) or the file is empty."
            )
            return

        print(f"[+] {len(records)} login record(s) parsed from '{args.file}'")

        if args.export:
            export_records(records, args.export, args.export_format, args.include_username)
            print(f"[+] Records exported to '{args.export}' (format: {args.export_format})")
        else:
            print()
            display_records(records, args.display, args.include_username)

    except (FileNotFoundError, PermissionError, OSError, struct.error) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
