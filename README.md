<div id="top" align="center">

[![Contributors][contributors-shield]](https://github.com/franckferman/LastLog-Audit/graphs/contributors)
[![Stargazers][stars-shield]](https://github.com/franckferman/LastLog-Audit/stargazers)
[![License][license-shield]](https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE)

<h3 align="center">LastLog-Audit</h3>
<p align="center">
  <em>Linux authentication log forensics: lastlog, wtmp, auth.log parsing and cross-source correlation.</em>
</p>

**[Site](https://franckferman.github.io/LastLog-Audit/) &middot; [Learning Lab](https://franckferman.github.io/LastLog-Audit/learn.html) &middot; [Training Scenarios](samples/README.md)**

</div>

---

## Table of Contents

<details open>
  <summary>Expand / Collapse</summary>
  <ol>
    <li><a href="#problem-statement">Problem Statement</a></li>
    <li><a href="#technical-background">Technical Background</a></li>
    <li><a href="#mitre-attck-mapping">MITRE ATT&CK Mapping</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#parameters">Parameters</a></li>
    <li><a href="#examples">Examples</a></li>
    <li><a href="#training-lab">Training Lab</a></li>
    <li><a href="#opsec-awareness">OPSEC Awareness</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

---

## Problem Statement

On Linux systems, the binary file `/var/log/lastlog` records the most recent successful authentication for every account by UID. This data is critical during security audits and incident response because it answers questions that no other single artefact answers efficiently:

- Which accounts have logged in recently, and from where?
- Which accounts are stale or dormant and represent an unnecessary attack surface?
- Has an adversary used a legitimate account (`T1078`) to blend into normal activity?
- Has a lastlog record been zeroed out (`T1070.006`) to erase evidence of access?

Standard tools like `lastlog(8)` produce human-readable output but offer no structured export, no programmatic filtering, and no offline analysis capability. **LastLog-Audit** solves this by providing a Python-native parser that operates directly on the binary format, supports offline analysis of files extracted from disk images, and exports results as CSV or plain text for downstream ingestion into SIEMs, spreadsheets, or audit reports.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Technical Background

### The lastlog Binary Format

`/var/log/lastlog` is a **sparse, fixed-size record database**. Each record is indexed directly by UID and occupies a fixed byte offset calculated as:

```
offset = UID * sizeof(struct lastlog)
```

The record structure (`struct lastlog` from `<lastlog.h>`) on most Linux distributions is:

| Field      | C Type     | Size (bytes) | Description                              |
|------------|------------|--------------|------------------------------------------|
| `ll_time`  | `uint32_t` | 4            | Unix timestamp of last successful login  |
| `ll_line`  | `char[32]` | 32           | Terminal device (e.g., `pts/0`, `tty1`)  |
| `ll_host`  | `char[256]`| 256          | Originating hostname or IP address       |

Total record size: **292 bytes**.

A record with `ll_time == 0` indicates the account has never authenticated. Because the file is sparse, UIDs with no record on disk also read as zero.

### What the Tool Audits

- **Last login timestamp** per UID, converted to ISO 8601 local time
- **Source terminal** (distinguishes local console logins from remote `pts` sessions)
- **Originating host** (hostname or IP address for remote logins via SSH, telnet, etc.)
- **Username resolution** via `pwd(3)` against the local passwd database (optional)

### Stale Account Detection

An account is operationally stale when it has not authenticated within the organisation's defined review window (commonly 90 days). Stale accounts are a persistent source of credential abuse because they are often excluded from active monitoring. LastLog-Audit surfaces these accounts by providing a last-login timestamp baseline that can be diffed against `/etc/passwd` to identify accounts that exist but have never or rarely authenticated.

### Offline Analysis

By accepting an arbitrary `--file` path, LastLog-Audit can parse lastlog files extracted from disk images or live memory captures, enabling forensic analysis without mounting a foreign system.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|---|---|---|
| T1078 | Valid Accounts | Identifies accounts with recent login activity that may indicate adversary use of legitimate credentials |
| T1078.003 | Valid Accounts: Local Accounts | Surfaces local account login history; dormant local accounts with unexpected recent logins are high-fidelity indicators |
| T1136 | Create Account | Newly created accounts (low UID with no lastlog record) may appear in the UID space without a corresponding login entry |
| T1531 | Account Access Removal | Accounts missing from a previous lastlog baseline may indicate tampering with the passwd database or the lastlog file itself |
| T1070.006 | Indicator Removal: Timestomp | Adversaries may zero lastlog records to erase evidence of access; an active account with timestamp=0 is anomalous |
| T1021 | Remote Services | Hostname and terminal fields reveal the origin and method of remote service authentications (SSH, etc.) |

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Installation

### Requirements

- Python 3.7 or later
- No external dependencies (standard library only: `argparse`, `csv`, `os`, `pwd`, `struct`, `datetime`)
- Read access to `/var/log/lastlog` (typically requires `root` or membership in the `adm` group)

### Clone

```bash
git clone https://github.com/franckferman/LastLog-Audit.git
cd LastLog-Audit
```

### Direct Download

```bash
curl -O https://raw.githubusercontent.com/franckferman/LastLog-Audit/stable/LastLogAudit.py
```

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
**Lastlog (default):**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-f` / `--file` | `PATH` | `/var/log/lastlog` | Path to the lastlog binary file. |
| `-u` / `--include-username` | flag | off | Resolve UIDs to usernames via the local passwd database. |

**Additional log sources:**

| Parameter | Type | Description |
|---|---|---|
| `--wtmp` | `FILE` | Parse a wtmp binary file for full login/logout history (struct utmp, 384 bytes/record). |
| `--auth-log` | `FILE` | Parse auth.log for SSH successes/failures and sudo commands. |
| `--correlate` | flag | Cross-reference lastlog + wtmp + auth.log. Requires `-f`, `--wtmp`, and `--auth-log`. |

**Output:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-d` / `--display` | `table` \| `line` | `table` | Stdout rendering format. |
| `-e` / `--export` | `OUTFILE` | - | Export results to file. |
| `-F` / `--export-format` | `csv` \| `txt` | `txt` | Export serialisation format. |

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Examples

### Lastlog (default)

```bash
# Display all login records
python3 LastLogAudit.py

# With username resolution
python3 LastLogAudit.py -u

# Offline analysis from a forensic disk image
python3 LastLogAudit.py -f /mnt/evidence/var/log/lastlog

# Export to CSV
python3 LastLogAudit.py -u -e audit.csv -F csv
```

### Wtmp (full login/logout history)

```bash
# Parse wtmp binary
python3 LastLogAudit.py --wtmp /var/log/wtmp

# From a sample
python3 LastLogAudit.py --wtmp samples/compromised.wtmp
```

### Auth.log (SSH successes/failures + sudo)

```bash
# Parse auth.log
python3 LastLogAudit.py --auth-log /var/log/auth.log

# From a sample
python3 LastLogAudit.py --auth-log samples/compromised.auth.log

# Export failures to CSV
python3 LastLogAudit.py --auth-log /var/log/auth.log -e auth_audit.csv -F csv
```

### Correlate (cross-reference all 3 sources)

```bash
# Full correlation analysis
python3 LastLogAudit.py \
  -f samples/compromised.lastlog \
  --wtmp samples/compromised.wtmp \
  --auth-log samples/compromised.auth.log \
  --correlate
```

The correlation report shows: external IPs across all sources, brute force indicators (failed/success ratio), open sessions (login without logout), sudo commands, and a risk assessment.

### Pipeline-friendly

```bash
# Grep for remote sessions only
python3 LastLogAudit.py -d line | grep -v '127.0.0.1'

# Extract IPs from auth.log failures
python3 LastLogAudit.py --auth-log /var/log/auth.log -d line | grep LOGIN_FAILED | cut -d',' -f4
```

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Training Lab

The `samples/` directory contains 9 pre-built lastlog binary files simulating real-world security scenarios. Each file is generated by `scripts/generate_samples.py` and can be analyzed offline without root access or a live system.

Use these as training exercises for SOC analysts, DFIR students, or as CTF challenges. Detailed solutions with IOC analysis, APT references, and MITRE ATT&CK mapping are in [`samples/README.md`](samples/README.md).

### Scenarios

| File | Scenario | Key indicators | MITRE |
|---|---|---|---|
| `clean_server.lastlog` | Normal production server | Internal IPs, business hours, 1 stale account | Baseline |
| `compromised.lastlog` | Active intrusion via Tor | Root from 185.220.101.34, dormant account reactivated, same-IP pivot | T1078, T1021 |
| `timestomped.lastlog` | Anti-forensic log tampering | Root record zeroed, future timestamp (2027) | T1070.006 |
| `apt_cozy_bear.lastlog` | APT29 / Cozy Bear style | 9-month dwell time, rotating C2 IPs, business-hours logins | G0016 |
| `apt_lazarus.lastlog` | Lazarus Group / APT38 style | Rapid multi-account compromise, single C2, NK timezone hours | G0032 |
| `insider_threat.lastlog` | Malicious insider | Same user accessing multiple accounts at 2-3 AM from home IP | Insider |
| `brute_force.lastlog` | Credential brute force | 5 accounts + root from same IP in 13 minutes | T1110 |
| `supply_chain.lastlog` | CI/CD pipeline compromise | Service accounts (jenkins/gitlab-runner UIDs) with interactive logins from GCP IPs | T1195 |
| `pentest_engagement.lastlog` | Authorized red team engagement | Methodical access from 10.10.14.x (HTB-style), initial access -> privesc -> lateral | Red team |

### Quick start

```bash
git clone https://github.com/franckferman/LastLog-Audit.git
cd LastLog-Audit

# Regenerate samples (optional, they are already included)
python3 scripts/generate_samples.py

# Analyze a scenario
python3 LastLogAudit.py --file samples/compromised.lastlog
```

### Example: APT29 / Cozy Bear

Long-dwell intrusion with rotating C2 infrastructure and business-hours access pattern:

```
$ python3 LastLogAudit.py --file samples/apt_cozy_bear.lastlog

[+] 7 login record(s) parsed from 'samples/apt_cozy_bear.lastlog'

Terminal              From                  Last Login
------------------------------------------------------------------
pts/0                 10.0.1.50             2026-03-25 10:15:00
pts/1                 10.0.1.101            2026-03-27 14:22:00
pts/2                 10.0.1.102            2026-03-26 08:45:00
pts/3                 193.29.56.122         2025-06-14 09:32:00
pts/3                 91.219.236.18         2025-09-03 10:47:00
pts/3                 5.45.65.52            2025-12-11 11:05:00
pts/3                 45.133.1.71           2026-03-22 09:58:00
```

What to notice: UIDs 1002-1005 all use `pts/3` from external IPs spanning June 2025 to March 2026. Same terminal, rotating IPs, quarterly check-ins during business hours. Classic APT persistence pattern.

### Example: Brute force

Rapid sequential compromise from a single attacker IP:

```
$ python3 LastLogAudit.py --file samples/brute_force.lastlog

[+] 7 login record(s) parsed from 'samples/brute_force.lastlog'

Terminal              From                  Last Login
------------------------------------------------------------------
pts/0                 194.26.29.113         2026-03-28 06:44:00
pts/1                 194.26.29.113         2026-03-28 06:31:00
pts/1                 10.0.1.101            2026-03-27 14:22:00
pts/2                 194.26.29.113         2026-03-28 06:33:00
pts/3                 194.26.29.113         2026-03-28 06:35:00
pts/4                 194.26.29.113         2026-03-28 06:38:00
pts/5                 194.26.29.113         2026-03-28 06:41:00
```

What to notice: 6 accounts logged in from `194.26.29.113` between 06:31 and 06:44 (13 minutes). Sequential terminal allocation (pts/1 through pts/5). Root (pts/0) compromised last at 06:44 - likely privilege escalation after lateral movement through low-privilege accounts.

### Example: Red team engagement

```
$ python3 LastLogAudit.py --file samples/pentest_engagement.lastlog

[+] 5 login record(s) parsed from 'samples/pentest_engagement.lastlog'

Terminal              From                  Last Login
------------------------------------------------------------------
pts/0                 10.10.14.7            2026-03-28 10:34:00
pts/1                 10.0.1.101            2026-03-27 14:22:00
pts/2                 10.10.14.7            2026-03-28 10:22:00
pts/3                 10.10.14.7            2026-03-28 10:28:00
pts/4                 10.10.14.7            2026-03-28 10:45:00
```

What to notice: all activity from `10.10.14.x` (HackTheBox / pentest VPN range). Methodical progression: initial access (10:22), second account (10:28), root (10:34), lateral move (10:45). Clean 23-minute operation during business hours.

### Regenerate or customize

The samples are deterministic. Edit `scripts/generate_samples.py` to add your own scenarios:

```python
def generate_my_scenario():
    records = {
        0:    (ts("2026-03-28 03:00"), "pts/0", "evil.attacker.com"),
        1000: (ts("2026-03-27 14:00"), "pts/1", "10.0.1.101"),
    }
    write_lastlog("samples/my_scenario.lastlog", records)
```

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## OPSEC Awareness

Log analysis is not magic. A sophisticated attacker with root access can tamper with all three log sources while preserving file metadata.

**[hidemyass](https://github.com/evilpan/hidemyass)** demonstrates this: it modifies individual records (not the whole file), preserves permissions, owner/group, and ctime/atime. Standard forensic tools see nothing.

```bash
# Wipe a specific IP from utmp, wtmp, and btmp
./hidemyass -uwb -a 185.220.101.34 -c

# Fake a lastlog timestamp
./hidemyass -l -n root -t 2026:03:15:09:30:00 -c
```

| Log source | Tamper-proof? | Detection |
|---|---|---|
| `/var/log/lastlog` | No | Compare against wtmp/auth.log; file integrity monitoring |
| `/var/log/wtmp` | No | Compare against auth.log; check session sequence gaps |
| `/var/log/auth.log` | No | Forward to remote syslog; check for missing time ranges |

**The only reliable defense is remote log forwarding.** If logs are shipped off-box in real time (rsyslog, syslog-ng, journald-remote), the attacker cannot retroactively delete them. File integrity monitoring (AIDE, Tripwire), immutable audit logs, and cross-source correlation (`--correlate`) add additional layers but are not sufficient alone.

The `--correlate` mode helps detect tampering: if auth.log shows a root login from an IP that lastlog does not, someone cleaned lastlog.

For full OPSEC analysis and defense-in-depth recommendations, see [`samples/README.md`](samples/README.md#opsec-awareness-why-log-analysis-has-limits).

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## License

This project is licensed under the GNU Affero General Public License v3.0.
See the [LICENSE](https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE) file for the full text.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">Back to top</a>)</p>

---

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/LastLog-Audit.svg?style=for-the-badge
[contributors-url]: https://github.com/franckferman/LastLog-Audit/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/franckferman/LastLog-Audit.svg?style=for-the-badge
[stars-url]: https://github.com/franckferman/LastLog-Audit/stargazers
[license-shield]: https://img.shields.io/github/license/franckferman/LastLog-Audit.svg?style=for-the-badge
[license-url]: https://github.com/franckferman/LastLog-Audit/blob/stable/LICENSE
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
