# 🔍 Incident Response Workbook

**On-demand investigation for a single device or user account, before, during and after a compromise.**

Streamlines unified events across device and user compromise into one chronological timeline. Pick an entity, pick a time range, no query editing.

---

## 🎯 Purpose

Investigating one suspect entity traditionally means opening a dozen separate queries across process, registry, network, identity, and mailbox telemetry — then lining up timestamps by hand. During an active incident that setup work is the bottleneck, not the analysis.

This collapses it into parameterized views. It answers **is something wrong, what kind, and when** — which is exactly what the Digital Forensics workbook needs as input.

---

## 🧭 Phases

Every row in the Device and User tabs is tagged with a **Phase**, so one view covers the whole attack:

| Phase | Answers |
| --- | --- |
| 1️⃣ Pre-Compromise | Was this entity targeted? Phishing, spray, brute force, exposed ports, risky downloads, blocked threats |
| 2️⃣ Initial Access | Did the attack get in? First execution, risky sign-ins, clicked phishing, token replay |
| 3️⃣ Post-Compromise | What happened next? Persistence, credential theft, lateral movement, mailbox abuse, exfil |

---

## 🖥️ Device Tab

| Category | Signals |
| --- | --- |
| **Targeting & Attempts** | Risky files delivered, admin ports reached from the internet, brute force, blocked threats |
| **Initial Access** | Office or script spawns, download and execute, malicious PowerShell, logons after failures |
| **Persistence** | Run keys, Winlogon, scheduled tasks, services, startup folder |
| **Credential Access** | LSASS dumping, Mimikatz, procdump, comsvcs, nanodump, pypykatz |
| **Defense Evasion** | Defender tampering, log clearing, auditpol, AMSI/ETW bypass |
| **Ransomware Prep** | Shadow copy deletion, recovery sabotage, backup destruction |
| **Discovery** | AD enumeration, BloodHound, Kerberos/SPN, cloud & host recon |
| **Lateral Movement** | PsExec, WMI, PowerShell remoting, admin shares |
| **Network Egress** | LOLBins reaching external infrastructure |
| **Backdoor Shells** | Reverse shells, named pipes, web shells |
| **Remote Access** | Unauthorized RATs and tunneling tools |
| **Defender Detections** | Native AV, ASR, Exploit Guard hits |
| **Local Accounts** | Account creation, privileged group additions |

Every row carries the initiating process, its command line, the spawned child process, and the file hash for immediate IOC extraction.

Four context panels sit under the timeline: **🖥️ Device Info** (OS, IPs, MAC, exposure, group, tags), **⚙️ Processes** (top 9 by runs), **📋 Details** (every command line) and **🎯 IOC** (top 9 domains and IPs by connections).

---

## 👤 User Tab

| Category | Signals |
| --- | --- |
| **Phishing** | Safe Links clicks and click-throughs in the timeline, plus a separate Phishing Received panel |
| **Token Replay** | One session used from several IPs or countries |
| **MFA Changes** | New authentication methods registered |
| **Account Takeover** | MFA removed, password resets, device unregistration |
| **Mailbox Rules** | Forwarding, redirect, and inbox rule creation |
| **Risky Sign-ins** | Entra ID risk detections and anomalous logons |
| **Rare Geography** | Sign-ins from countries unusual for this specific user |
| **Malicious IPs** | Logons correlated against threat-intel feeds |
| **OAuth Consent** | App permission grants used for persistence |
| **Mailbox Export** | eDiscovery and bulk mail export |
| **Containment Status** | Separate tile row: sessions revoked, password and MFA reset, account disabled |

---

## 📤 Data Exfiltration Tab

Exfiltration rarely shows up as one obvious event — it's a sequence of collect, stage, compress, then move, and the move often uses a different channel than the one being monitored. An attacker who can't reach a file-sharing site uses email; a user walking out with data uses a USB drive. This tab covers eight channels in one view so the pattern is visible rather than scattered, and it applies equally to external intrusion and insider risk.

| Channel | Catches |
| --- | --- |
| **File-Sharing / Paste Uploads** | WeTransfer, MEGA, anonymous file hosts, paste sites, personal cloud storage |
| **Exfil Tooling** | `rclone`, `megacmd`, `azcopy`, WinSCP, FTP clients, cloud CLIs with an upload verb |
| **Mass Archiving** | Bulk compression, weighted when password-protected or targeting sensitive paths |
| **Removable Media** | USB mount events and bulk writes to non-system drives |
| **Bulk Cloud Download** | High-volume SharePoint / OneDrive file downloads |
| **Outbound Attachments** | External attachment volume, weighted higher for personal webmail recipients |
| **Mail Forwarding Rules** | Inbox and transport rules forwarding externally — the classic BEC method |
| **Connection Fan-Out** | High connection counts from non-browser processes, as a volume proxy |

This tab spans both planes — endpoint channels (tooling, archiving, removable media) and identity channels (cloud download, forwarding rules, attachments) — so it's the natural bridge when an intrusion moves from access to theft.

---

## 🔄 Pivoting

**The tabs are designed to pivot into each other.** Most intrusions cross the endpoint and identity planes:

- A risky sign-in names a device → open the device tab
- A compromised endpoint names a logged-in account → open the user tab
- Either one showing collection or staging → open the exfil tab to see if data actually left

Start with whichever entity you have and follow the trail.

---

## ⚙️ Parameters

| Parameter | Notes |
| --- | --- |
| `DeviceName` | Query-backed dropdown from `DeviceInfo` |
| `UserPrincipalName` | Query-backed dropdown from `SigninLogs` |
| `TimeRange` | Binds to `TimeGenerated` |

Query-backed rather than free text — a typo returns an empty result set that looks identical to a clean entity.

---

## 📊 Visualization of the Dashboard

Here's an example of the [Device Investigation](Device%20Investigation/Device%20Investigation.md) workbook in action:

![Device Investigation dashboard](Device%20Investigation/Image/image.png)
