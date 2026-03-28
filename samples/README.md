# Training Lab - Scenario Solutions

This directory contains 9 pre-built lastlog binary files simulating real-world attack scenarios. Each file can be analyzed with LastLog-Audit without root access or a live system.

Use these as SOC analyst exercises, DFIR training modules, or CTF challenges.

```bash
python3 LastLogAudit.py -f samples/<scenario>.lastlog
```

---

## 1. clean_server.lastlog - Baseline

**Context:** Production Linux web server. Standard admin team of 4 people. Internal network 10.0.1.0/24.

**What you see:**
```
pts/0    10.0.1.50     2026-03-15 09:30:00    (UID 0 - root)
pts/1    10.0.1.101    2026-03-27 14:22:00    (UID 1000)
pts/2    10.0.1.102    2026-03-26 08:45:00    (UID 1001)
pts/0    10.0.1.103    2026-03-20 17:10:00    (UID 1002)
pts/3    10.0.1.50     2026-01-05 11:00:00    (UID 1003)
```

**Analysis:**
- All logins from internal IPs (10.0.1.x) - expected
- All during business hours - expected
- UID 1003 last seen January 5 - stale account (83 days inactive)
- Root login from management workstation (10.0.1.50) - normal if documented

**Action items:**
- Investigate UID 1003: should the account be disabled?
- Verify root SSH access policy (should root login be disabled in sshd_config?)

**Verdict:** Normal activity. One stale account to review.

---

## 2. compromised.lastlog - Active Intrusion via Tor

**Context:** Same server as baseline, but compromised. Attacker gained access through an exposed SSH service.

**What you see:**
```
pts/0    185.220.101.34    2026-03-28 03:47:00    (UID 0 - root)
pts/1    10.0.1.101        2026-03-27 14:22:00    (UID 1000)
pts/2    10.0.1.102        2026-03-26 08:45:00    (UID 1001)
pts/0    10.0.1.103        2026-03-25 17:10:00    (UID 1002)
pts/3    10.0.1.50         2026-01-05 11:00:00    (UID 1003)
pts/4    45.153.160.140    2026-03-28 03:52:00    (UID 1005)
pts/5    185.220.101.34    2026-03-28 04:01:00    (UID 1006)
```

**Red flags:**
1. **Root (UID 0) from 185.220.101.34 at 03:47** - This is a known Tor exit node. Root should never login from external IPs, especially at 3 AM.
2. **UID 1005 from 45.153.160.140 at 03:52** - Another Tor exit node. This account was dormant (not present in the clean baseline). Reactivation of a dormant account is a T1078 indicator.
3. **UID 1006 from 185.220.101.34 at 04:01** - Same IP as the root login. This suggests the attacker created a new account (T1136) or compromised another one after gaining root.
4. **UID 1004 is absent** - The UID gap (1003 -> 1005) suggests UID 1004 exists but has never logged in. Potential backdoor account (T1136).
5. **Timeline:** 03:47 -> 03:52 -> 04:01. All activity within a 14-minute window in the middle of the night.

**MITRE ATT&CK:**
- T1078 (Valid Accounts) - Dormant account reuse
- T1021.004 (Remote Services: SSH) - External SSH access
- T1136 (Create Account) - Potential phantom account at UID 1004
- T1078.003 (Local Accounts) - Multiple local accounts compromised

**Threat intel:**
- 185.220.101.34 - Tor exit node (check against threat feeds)
- 45.153.160.140 - Tor exit node (Calyx Institute range)

**Verdict:** Active intrusion. Immediate incident response required.

---

## 3. timestomped.lastlog - Anti-Forensic Log Tampering

**Context:** Server where an attacker has attempted to cover their tracks by manipulating lastlog records.

**What you see:**
```
pts/1    10.0.1.101    2026-03-27 14:22:00    (UID 1000)
pts/0    10.0.1.200    2027-01-01 00:00:00    (UID 1001)
pts/2    10.0.1.102    2026-03-20 09:30:00    (UID 1002)
```

**Red flags:**
1. **Root (UID 0) is missing** - On any active server, root should have a lastlog record. A zeroed record (timestamp=0) means either root has literally never logged in (unlikely) or the record was deliberately wiped. This is T1070.006 (Indicator Removal: Timestomp).
2. **UID 1001 timestamp is 2027-01-01** - A date in the future. This indicates clock manipulation or deliberate forgery of the lastlog record. The attacker may have modified the binary file directly.
3. **UID 1001 from 10.0.1.200** - This IP is outside the normal admin range (10.0.1.50, .101-.103). New source.

**MITRE ATT&CK:**
- T1070.006 (Indicator Removal: Timestomp) - Root record zeroed
- T1070 (Indicator Removal) - General evidence destruction

**Investigation next steps:**
- Check `/var/log/auth.log` and `/var/log/wtmp` for root login evidence that lastlog no longer shows
- Compare lastlog file mtime against expected modification times
- Check file integrity monitoring (AIDE, Tripwire) for lastlog modifications

**Verdict:** Active anti-forensic activity. Attacker had root access and attempted evidence destruction.

---

## 4. apt_cozy_bear.lastlog - APT29 / Cozy Bear Style

**Context:** Government research server. Long-term compromise discovered during a routine audit.

**What you see:**
```
pts/0    10.0.1.50       2026-03-25 10:15:00    (UID 0 - root)
pts/1    10.0.1.101      2026-03-27 14:22:00    (UID 1000)
pts/2    10.0.1.102      2026-03-26 08:45:00    (UID 1001)
pts/3    193.29.56.122   2025-06-14 09:32:00    (UID 1002)
pts/3    91.219.236.18   2025-09-03 10:47:00    (UID 1003)
pts/3    5.45.65.52      2025-12-11 11:05:00    (UID 1004)
pts/3    45.133.1.71     2026-03-22 09:58:00    (UID 1005)
```

**Red flags:**
1. **UIDs 1002-1005 all use pts/3** - Same terminal across 4 different accounts from 4 different external IPs. This is not normal user behavior.
2. **Rotating IP addresses** - Each login from a different IP: 193.29.56.122, 91.219.236.18, 5.45.65.52, 45.133.1.71. Classic C2 infrastructure rotation.
3. **9-month dwell time** - From June 2025 to March 2026. The attacker maintained persistent access for nearly a year.
4. **Quarterly check-ins** - June, September, December, March. Roughly every 3 months. This is a deliberate low-and-slow access pattern to avoid detection.
5. **Business hours only** - 09:32, 10:47, 11:05, 09:58. All logins during the target's working hours to blend with legitimate traffic.
6. **Internal accounts untouched** - Root and UID 1000-1001 show normal internal activity. The attacker used separate accounts (1002-1005) and did not touch admin accounts.

**APT29 (Cozy Bear) TTPs:**
- Long dwell time (months to years)
- Low-and-slow access cadence
- Rotating C2 infrastructure
- Operating during victim's business hours
- Avoiding privileged accounts to stay under the radar

**Reference:** MITRE ATT&CK Group [G0016](https://attack.mitre.org/groups/G0016/)

**MITRE ATT&CK:**
- T1078 (Valid Accounts) - Compromised service accounts
- T1071 (Application Layer Protocol) - SSH as C2 channel
- T1027 (Obfuscated Files or Information) - Infrastructure rotation for evasion

**Verdict:** Advanced persistent threat. Likely state-sponsored. 9-month undetected compromise. Requires full forensic investigation and network-wide threat hunt.

---

## 5. apt_lazarus.lastlog - Lazarus Group / APT38 Style

**Context:** Cryptocurrency exchange backend server.

**What you see:**
```
pts/0    175.45.176.3    2026-03-27 22:14:00    (UID 0 - root)
pts/1    10.0.1.101      2026-03-27 14:00:00    (UID 1000)
pts/2    175.45.176.3    2026-03-27 21:45:00    (UID 1001)
pts/3    175.45.176.3    2026-03-27 22:03:00    (UID 1002)
pts/4    175.45.176.3    2026-03-27 22:18:00    (UID 1003)
pts/5    175.45.176.3    2026-03-27 22:31:00    (UID 1004)
```

**Red flags:**
1. **Single external IP across 5 accounts** - 175.45.176.3 logged into 5 different accounts including root. One source, multiple targets = systematic compromise.
2. **Rapid escalation** - 21:45 -> 22:03 -> 22:14 -> 22:18 -> 22:31. Five accounts in 46 minutes. This is not brute force (too slow for that) but not careful either - the attacker had valid credentials.
3. **175.45.176.3** - This is a DPRK (North Korean) IP range (Star JV / Ryugyong-dong). Lazarus Group is attributed to DPRK's Reconnaissance General Bureau.
4. **Evening UTC hours** - 21:45-22:31 UTC = early morning in UTC+9 (Pyongyang). Consistent with NK operating hours.
5. **Root compromised** - Full system control obtained.
6. **Crypto exchange target** - Lazarus Group is notorious for targeting cryptocurrency platforms for financial theft (e.g., Ronin Bridge, Harmony Horizon).

**Lazarus Group TTPs:**
- Financial motivation (cryptocurrency theft)
- Single C2 hop (less infrastructure rotation than APT29)
- Rapid multi-account compromise
- Operating in UTC+8.5/+9 hours
- Targeting exchange hot wallets and backend infrastructure

**Reference:** MITRE ATT&CK Group [G0032](https://attack.mitre.org/groups/G0032/)

**Verdict:** Lazarus-style financially motivated intrusion. Immediate containment: isolate server, freeze hot wallets, preserve evidence.

---

## 6. insider_threat.lastlog - Malicious Insider

**Context:** Corporate file server. An employee with legitimate access begins acting outside their normal pattern.

**What you see:**
```
pts/0    10.0.1.50       2026-03-15 09:30:00    (UID 0 - root)
pts/0    82.65.140.27    2026-03-28 02:15:00    (UID 1000)
pts/1    10.0.1.101      2026-03-27 14:22:00    (UID 1001)
pts/2    10.0.1.102      2026-03-26 08:45:00    (UID 1002)
pts/1    82.65.140.27    2026-03-28 02:47:00    (UID 1003)
pts/2    82.65.140.27    2026-03-28 03:12:00    (UID 1004)
```

**Red flags:**
1. **UID 1000 from external IP at 02:15** - This user normally logs in from 10.0.1.101 during business hours. Now accessing from 82.65.140.27 (residential ISP) at 2 AM.
2. **Same external IP across 3 accounts** - UID 1000, 1003, and 1004 all from 82.65.140.27. One person using multiple accounts.
3. **2-3 AM activity** - Outside any reasonable business hours. Deliberate timing to avoid observation.
4. **Pattern shift** - Compare with clean_server baseline: UID 1000 was 10.0.1.101 during business hours, now 82.65.140.27 at night.

**Insider threat indicators:**
- Access from personal IP (residential, not corporate VPN)
- Using credentials for accounts they shouldn't have access to
- Off-hours activity
- Same source IP across multiple accounts

**MITRE ATT&CK:**
- T1078 (Valid Accounts) - Legitimate credentials used maliciously
- T1530 (Data from Cloud Storage Object) - Potential data exfiltration motive
- T1048 (Exfiltration Over Alternative Protocol) - Off-hours access suggests data theft

**Verdict:** Insider threat. Correlate with DLP logs, VPN logs, and HR records. Preserve evidence before confrontation.

---

## 7. brute_force.lastlog - Credential Brute Force

**Context:** Web server with SSH exposed to the internet.

**What you see:**
```
pts/0    194.26.29.113    2026-03-28 06:44:00    (UID 0 - root)
pts/1    194.26.29.113    2026-03-28 06:31:00    (UID 33 - www-data)
pts/1    10.0.1.101       2026-03-27 14:22:00    (UID 1000)
pts/2    194.26.29.113    2026-03-28 06:33:00    (UID 1001)
pts/3    194.26.29.113    2026-03-28 06:35:00    (UID 1002)
pts/4    194.26.29.113    2026-03-28 06:38:00    (UID 1003)
pts/5    194.26.29.113    2026-03-28 06:41:00    (UID 1004)
```

**Red flags:**
1. **Same IP, 6 accounts, 13 minutes** - 194.26.29.113 successfully logged into www-data (06:31), UID 1001 (06:33), 1002 (06:35), 1003 (06:38), 1004 (06:41), then root (06:44). Sequential, ~2 min apart.
2. **www-data (UID 33) has an interactive login** - Service accounts like www-data should never have interactive SSH sessions. This means either: weak password, or credential reuse from a web app compromise.
3. **Sequential terminal allocation** - pts/1 through pts/5. Each login opens a new terminal, confirming these are separate sessions, not reconnections.
4. **Root compromised last** - The attacker started with low-privilege accounts and escalated. Root at 06:44 was likely achieved via sudo/SUID after gaining a foothold.

**MITRE ATT&CK:**
- T1110 (Brute Force) - Multiple account compromise from single source
- T1078 (Valid Accounts) - Service account abuse (www-data)
- T1548 (Abuse Elevation Control Mechanism) - Privilege escalation to root

**Verdict:** Successful brute force attack. Block 194.26.29.113, rotate all credentials, audit sudo/SUID binaries.

---

## 8. supply_chain.lastlog - CI/CD Pipeline Compromise

**Context:** Application server with Jenkins and GitLab Runner service accounts.

**What you see:**
```
pts/0    10.0.1.50     2026-03-20 09:30:00    (UID 0 - root)
pts/0    34.89.172.44  2026-03-28 01:17:00    (UID 110)
pts/1    35.205.94.18  2026-03-28 01:22:00    (UID 111)
pts/1    10.0.1.101    2026-03-27 14:22:00    (UID 1000)
pts/2    10.0.1.102    2026-03-26 08:45:00    (UID 1001)
```

**Red flags:**
1. **UID 110 and 111 with interactive logins** - These are typically service account UIDs (jenkins, gitlab-runner, etc.). Service accounts run automated pipelines - they should never have interactive SSH sessions (pts/0, pts/1).
2. **Source IPs: 34.89.x.x and 35.205.x.x** - These are Google Cloud Platform (GCP) IP ranges. If your CI/CD does not run on GCP, this is anomalous.
3. **01:17 and 01:22 AM** - CI/CD jobs typically run on triggers (push, merge), not at 1 AM unless scheduled. Check pipeline schedules.
4. **5-minute gap** - UID 110 at 01:17, UID 111 at 01:22. Attacker compromised one service account, then pivoted to another.

**Attack scenario:**
Attacker compromised a CI/CD pipeline (e.g., malicious dependency, poisoned Dockerfile, compromised GitHub Action) and used the pipeline's credentials to SSH into the production server.

**MITRE ATT&CK:**
- T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain) - Pipeline as attack vector
- T1078.004 (Valid Accounts: Cloud Accounts) - Cloud-sourced credentials
- T1021.004 (Remote Services: SSH) - Interactive SSH from service accounts

**Verdict:** Supply chain compromise. Audit all CI/CD pipelines, rotate service account credentials, review recent deployments.

---

## 9. pentest_engagement.lastlog - Authorized Red Team

**Context:** Authorized penetration test by franckferman during an agreed testing window.

**What you see:**
```
pts/0    10.10.14.7    2026-03-28 10:34:00    (UID 0 - root)
pts/1    10.0.1.101    2026-03-27 14:22:00    (UID 1000)
pts/2    10.10.14.7    2026-03-28 10:22:00    (UID 1001)
pts/3    10.10.14.7    2026-03-28 10:28:00    (UID 1002)
pts/4    10.10.14.7    2026-03-28 10:45:00    (UID 1003)
```

**What to notice:**
1. **10.10.14.x range** - This is the HackTheBox / pentest VPN subnet. In a real engagement, this would be the pentester's VPN IP assigned by the testing platform or the client's VPN.
2. **Methodical progression** - Initial access via UID 1001 (10:22), lateral to UID 1002 (10:28), privilege escalation to root (10:34), post-exploitation lateral to UID 1003 (10:45). Clean 23-minute operation.
3. **Business hours** - Testing during the agreed window (10 AM).
4. **Single source** - All activity from one IP, consistent with a single operator.

**This is what a professional pentest looks like in logs.** Compare with the brute_force scenario: the pentester is more methodical (6-min gaps vs 2-min), uses a VPN (not raw internet IP), and operates during agreed hours.

**Verdict:** Authorized activity. Verify against the Rules of Engagement document.

---

## OPSEC Awareness: Why Log Analysis Has Limits

### The attacker's perspective

A sophisticated attacker with root access will not leave clean traces in lastlog, wtmp, or auth.log. Tools exist specifically to tamper with these files while preserving file metadata (permissions, timestamps, ownership).

**[hidemyass](https://github.com/evilpan/hidemyass)** is a post-exploitation tool that demonstrates this:

```bash
# Wipe a specific IP from utmp, wtmp, and btmp
./hidemyass -uwb -a 185.220.101.34 -c

# Modify a lastlog record to fake a different login time
./hidemyass -l -n root -t 2026:03:15:09:30:00 -c

# Print all records to verify tampering
./hidemyass -uwbl -p
```

hidemyass modifies individual records (not the whole file), preserves file permissions, owner/group, and ctime/atime. The result: `last`, `lastlog`, `who`, and `w` all show clean output. Standard forensic tools see nothing.

### What this means for defenders

LastLog-Audit and similar tools are valuable for detection, but they are **not tamper-proof**:

| Log source | Can be tampered by root? | Detection of tampering |
|---|---|---|
| `/var/log/lastlog` | Yes (hidemyass, direct binary edit) | Compare against wtmp/auth.log; check file integrity (AIDE, Tripwire) |
| `/var/log/wtmp` | Yes (hidemyass, utmpdump + edit + utmpdump -r) | Compare against auth.log; check for gaps in session sequence |
| `/var/log/auth.log` | Yes (sed, truncate, or log poisoning) | Forward logs to remote syslog (the attacker can't reach); check for missing time ranges |
| All local logs | Yes if attacker has root | **Remote logging is the only reliable defense** |

### Defense in depth

1. **Forward logs to a remote syslog server** (rsyslog, syslog-ng, journald-remote). If logs are shipped off-box in real time, the attacker cannot retroactively delete them.
2. **File integrity monitoring** (AIDE, Tripwire, OSSEC) on `/var/log/lastlog`, `/var/log/wtmp`, and `/var/log/auth.log`. Alert on any modification outside expected patterns.
3. **Immutable audit logs** (auditd with `append_only` on the log partition, or write-once storage).
4. **Cross-reference multiple sources**. Use `--correlate` to compare lastlog, wtmp, and auth.log. Discrepancies between sources are a strong indicator of tampering. If auth.log shows a root login from an IP that lastlog does not, someone cleaned lastlog.
5. **Assume compromise**. Log analysis is one layer. Network telemetry (NetFlow, DNS logs), endpoint detection (EDR), and memory forensics provide independent evidence that an attacker cannot wipe from the same vantage point.

### The training takeaway

These sample scenarios are designed with clean, untampered logs so you can learn the analysis patterns. In real incidents, expect missing or altered records. The skill is recognizing what should be there but isn't - and that requires understanding the baseline (see `clean_server.lastlog`).
