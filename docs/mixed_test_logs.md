# Mixed Test Logs — 10 Wazuh Alerts

10 real Wazuh-format alerts for testing the model pipeline.
Run with: `python src/test_mixed.py`

---

## Log 1 — BENIGN: SSH Successful Login

```json
{
  "@timestamp": "2026-05-22T09:15:10.000+0000",
  "location": "/var/log/auth.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "sshd", "timestamp": "2026-05-22T10:15:10+01:00" },
  "decoder": { "parent": "sshd", "name": "sshd" },
  "rule": {
    "id": "5715", "level": 3, "firedtimes": 1, "mail": false,
    "description": "sshd: authentication success.",
    "groups": ["syslog", "sshd", "authentication_success"]
  },
  "data": { "srcip": "192.168.1.30", "dstuser": "ubuntu", "src_port": "55100" },
  "location": "/var/log/auth.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 5715 |
| Rule Level | 3 (low) |
| Decoder | sshd |
| Source IP | 192.168.1.30 |
| Location | /var/log/auth.log |
| Expected verdict | **BENIGN** |

---

## Log 2 — BENIGN: Normal Web GET 200

```json
{
  "@timestamp": "2026-05-22T14:05:33.000+0000",
  "location": "/var/log/apache2/access.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "decoder": { "parent": "web-accesslog", "name": "web-accesslog" },
  "rule": {
    "id": "31100", "level": 0, "firedtimes": 1, "mail": false,
    "description": "Web server 200 OK response.",
    "groups": ["web", "accesslog"]
  },
  "data": {
    "srcip": "192.168.1.30", "dstip": "192.168.1.212",
    "http": { "http_method": "GET", "status": "200", "hostname": "isiamin.tn" },
    "url": "/index.php"
  },
  "location": "/var/log/apache2/access.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 31100 |
| Rule Level | 0 (informational) |
| Decoder | web-accesslog |
| HTTP Method | GET |
| HTTP Status | 200 OK |
| Expected verdict | **BENIGN** |

---

## Log 3 — BENIGN: APT Package Update

```json
{
  "@timestamp": "2026-05-22T03:00:12.000+0000",
  "location": "/var/log/dpkg.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "dpkg", "timestamp": "2026-05-22T04:00:12+01:00" },
  "decoder": { "parent": "dpkg", "name": "dpkg" },
  "rule": {
    "id": "2930", "level": 3, "firedtimes": 1, "mail": false,
    "description": "System package updated.",
    "groups": ["syslog", "dpkg", "package_management"]
  },
  "data": { "package": "openssl", "version": "3.0.2-0ubuntu1.15" },
  "location": "/var/log/dpkg.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 2930 |
| Rule Level | 3 (low) |
| Decoder | dpkg |
| Package | openssl |
| Expected verdict | **BENIGN** |

---

## Log 4 — ATTACK (Scanning): Nmap OS Detection

```json
{
  "@timestamp": "2026-05-22T10:05:44.000+0000",
  "location": "/var/log/suricata/fast.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "suricata", "timestamp": "2026-05-22T11:05:44+01:00" },
  "decoder": { "parent": "suricata", "name": "suricata" },
  "rule": {
    "id": "40102", "level": 6, "firedtimes": 12, "mail": false,
    "description": "Nmap OS detection scan detected.",
    "groups": ["recon", "scan", "nmap", "ids"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstip": "192.168.1.212",
    "src_port": "43200", "dest_port": "80", "proto": "TCP"
  },
  "location": "/var/log/suricata/fast.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 40102 |
| Rule Level | 6 (medium) |
| Decoder | suricata |
| Attack type | Reconnaissance / OS fingerprinting |
| Source IP | 192.168.1.50 |
| Expected verdict | **Scanning** *(low confidence — known edge case)* |

> **Note:** Nmap via suricata decoder overlaps with Exfiltration features. Model confidence ~55%. Anomaly detector does not flag it, so the 97% threshold rule does not activate. This is a known limitation.

---

## Log 5 — ATTACK (Scanning): iptables Port Scan

```json
{
  "@timestamp": "2026-05-22T10:28:20.000+0000",
  "location": "/var/log/iptables.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "kernel", "timestamp": "2026-05-22T11:28:20+01:00" },
  "decoder": { "parent": "kernel", "name": "kernel" },
  "rule": {
    "id": "100200", "level": 8, "firedtimes": 1, "mail": false,
    "description": "iptables: Port scan detected",
    "groups": ["iptables", "portscan", "recon"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstip": "192.168.1.212",
    "src_port": "33444", "dest_port": "9999",
    "proto": "TCP", "action": "PORTSCAN"
  },
  "location": "/var/log/iptables.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 100200 |
| Rule Level | 8 (high) |
| Decoder | kernel |
| Action | PORTSCAN |
| Source IP | 192.168.1.50 |
| Expected verdict | **Scanning** (100% confidence) |

---

## Log 6 — ATTACK (CredentialAccess): SSH Brute Force

```json
{
  "@timestamp": "2026-05-22T11:11:27.000+0000",
  "location": "/var/log/auth.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "sshd", "timestamp": "2026-05-22T12:11:27+01:00" },
  "decoder": { "parent": "sshd", "name": "sshd" },
  "rule": {
    "id": "5763", "level": 10, "firedtimes": 20, "mail": false,
    "description": "sshd: brute force trying to get access to the system. Authentication failed.",
    "groups": ["sshd", "authentication_failed", "brute_force", "syslog"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstuser": "root",
    "src_port": "60524"
  },
  "location": "/var/log/auth.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 5763 |
| Rule Level | 10 (critical) |
| Decoder | sshd |
| firedtimes | 20 (repeated attempts) |
| Target user | root |
| MITRE | T1110 — Brute Force |
| Expected verdict | **CredentialAccess** (100% confidence) |

---

## Log 7 — ATTACK (CredentialAccess): PAM Login Failure

```json
{
  "@timestamp": "2026-05-22T11:11:22.000+0000",
  "location": "/var/log/auth.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "sshd", "timestamp": "2026-05-22T12:11:22+01:00" },
  "decoder": { "name": "pam" },
  "rule": {
    "id": "5503", "level": 5, "firedtimes": 1, "mail": false,
    "description": "PAM: User login failed.",
    "groups": ["pam", "authentication_failed", "syslog"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstuser": "root",
    "uid": "0", "euid": "0", "tty": "ssh"
  },
  "location": "/var/log/auth.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 5503 |
| Rule Level | 5 (medium) |
| Decoder | pam |
| firedtimes | 1 (single failure) |
| Target user | root |
| Expected verdict | **CredentialAccess** *(low confidence — known edge case)* |

> **Note:** A single PAM failure shares many features with a normal SSH event (same location, same program). Model confidence ~80%, below the 97% trigger. The anomaly detector does not flag it either.

---

## Log 8 — ATTACK (Exfiltration): DNS Tunneling

```json
{
  "@timestamp": "2026-05-22T13:22:05.000+0000",
  "location": "/var/log/named.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "predecoder": { "program_name": "named", "timestamp": "2026-05-22T14:22:05+01:00" },
  "decoder": { "parent": "named", "name": "named" },
  "rule": {
    "id": "100300", "level": 8, "firedtimes": 30, "mail": false,
    "description": "Possible data exfiltration via DNS tunneling.",
    "groups": ["dns", "tunneling", "exfiltration", "ids"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstip": "8.8.8.8",
    "src_port": "54321", "dest_port": "53", "proto": "UDP",
    "dns": { "rrtype": "TXT" },
    "flow": {
      "pkts_toserver": 5, "pkts_toclient": 80,
      "bytes_toserver": 800, "bytes_toclient": 95000
    }
  },
  "location": "/var/log/named.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 100300 |
| Rule Level | 8 (high) |
| Decoder | named |
| Protocol | UDP / DNS TXT |
| Bytes to client | 95,000 (anomalous volume) |
| Anomaly flag | YES |
| MITRE | T1048 — Exfiltration Over Alternative Protocol |
| Expected verdict | **Exfiltration** (100% confidence) |

---

## Log 9 — ATTACK (WebAttack): SQL Injection

```json
{
  "@timestamp": "2026-05-22T10:30:54.000+0000",
  "location": "/var/log/apache2/other_vhosts_access.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "decoder": { "parent": "web-accesslog", "name": "web-accesslog" },
  "rule": {
    "id": "31106", "level": 6, "firedtimes": 1, "mail": false,
    "description": "A web attack returned code 200 (success).",
    "groups": ["web", "accesslog", "attack"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstip": "192.168.1.212",
    "http": { "http_method": "GET", "status": "200", "hostname": "isiamin.tn" },
    "url": "/index.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x71%2CTABLE_NAME%29%20FROM%20information_schema.tables--"
  },
  "location": "/var/log/apache2/other_vhosts_access.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 31106 |
| Rule Level | 6 (medium) |
| Decoder | web-accesslog |
| HTTP Method | GET |
| HTTP Status | 200 (attack succeeded) |
| Payload | UNION SELECT on information_schema |
| MITRE | T1190 — Exploit Public-Facing Application |
| Expected verdict | **WebAttack** (98.5% confidence) |

---

## Log 10 — ATTACK (WebAttack): Web Shell Execution

```json
{
  "@timestamp": "2026-05-22T10:55:18.000+0000",
  "location": "/var/log/apache2/other_vhosts_access.log",
  "agent": { "id": "001", "name": "ubuntu", "ip": "192.168.1.212" },
  "decoder": { "parent": "web-accesslog", "name": "web-accesslog" },
  "rule": {
    "id": "31166", "level": 9, "firedtimes": 3, "mail": false,
    "description": "Web shell access detected.",
    "groups": ["web", "accesslog", "attack", "webshell"]
  },
  "data": {
    "srcip": "192.168.1.50", "dstip": "192.168.1.212",
    "http": { "http_method": "POST", "status": "200", "hostname": "isiamin.tn" },
    "url": "/uploads/shell.php?cmd=whoami"
  },
  "location": "/var/log/apache2/other_vhosts_access.log"
}
```

| Field | Value |
|---|---|
| Rule ID | 31166 |
| Rule Level | 9 (critical) |
| Decoder | web-accesslog |
| HTTP Method | POST |
| URL | /uploads/shell.php?cmd=whoami |
| MITRE | T1505.003 — Web Shell |
| Expected verdict | **WebAttack** (99% confidence) |

---

## Summary

| # | Alert | True Class | Anomaly Flag | Family Confidence | Final Verdict | Result |
|---|---|---|---|---|---|---|
| 1 | SSH login success | BENIGN | NO | 90% (CredentialAccess) | **BENIGN** | CORRECT |
| 2 | Normal web GET 200 | BENIGN | NO | 96% (WebAttack) | **BENIGN** | CORRECT |
| 3 | APT package update | BENIGN | NO | 50% (CredentialAccess) | **BENIGN** | CORRECT |
| 4 | Nmap OS detection | Scanning | NO | 55% (Scanning) | BENIGN | WRONG |
| 5 | iptables port scan | Scanning | NO | 100% (Scanning) | **Scanning** | CORRECT |
| 6 | SSH brute force | CredentialAccess | NO | 100% (CredentialAccess) | **CredentialAccess** | CORRECT |
| 7 | PAM login failed | CredentialAccess | NO | 80% (CredentialAccess) | BENIGN | WRONG |
| 8 | DNS tunneling | Exfiltration | YES | 100% (Exfiltration) | **Exfiltration** | CORRECT |
| 9 | SQL injection | WebAttack | NO | 98% (WebAttack) | **WebAttack** | CORRECT |
| 10 | Web shell | WebAttack | NO | 99% (WebAttack) | **WebAttack** | CORRECT |

**Overall: 8/10 correct**

---

## Decision Logic

```
IF   anomaly_score >= threshold (-0.1558)    → flag as ATTACK → use family class
ELIF family_confidence >= 97%                → flag as ATTACK → use family class
ELSE                                         → BENIGN
```

---

## Known Edge Cases

### Log 4 — Nmap OS detection (missed)
- Nmap via `suricata` decoder overlaps with Exfiltration training patterns
- Model splits 55% Scanning / 45% Exfiltration → below 97% trigger
- Anomaly detector does not flag it → final verdict = BENIGN (false negative)

### Log 7 — PAM login failed (missed)
- Single PAM failure shares the same `location`, `program_name`, and `decoder` as a normal SSH event
- Model confidence 80% → below 97% trigger
- Anomaly detector does not flag it → final verdict = BENIGN (false negative)

### Why these two are hard
The family classifier was trained without BENIGN samples (`--drop-benign`).
It cannot distinguish a legitimate SSH login (Log 1) from a PAM failure (Log 7) purely by features — both use the same log file, same decoder, same program. Only `rule_id`, `rule_level`, and `firedtimes` differ, and these alone are not enough to cross the confidence threshold when the model has uncertainty.

---

## Severity Map

| Class | Severity | Action recommended |
|---|---|---|
| BENIGN | LOW | No action |
| Scanning | MEDIUM | Monitor source IP, review firewall rules |
| CredentialAccess | HIGH | Block source IP, check for successful logins |
| Exfiltration | HIGH | Isolate host, review outbound connections |
| WebAttack | HIGH | Review web server logs, patch application |
