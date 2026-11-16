# 🛡️ Detection Engineering & Threat Hunting

A curated library of KQL detection rules, threat hunting queries, and Sentinel/Defender workbooks built to detect real-world attacks in enterprise environments.

---

## 🎯 About

This repo contains detection engineering and threat hunting content developed for Microsoft Sentinel and Microsoft Defender XDR. Detections are mapped to MITRE ATT&CK and focused on threats actively targeting enterprise environments — including external tenant impersonation, identity attacks, EDR evasion, and living-off-the-land techniques.

---

## 🔍 What's Inside

### ⚡ Custom Detection Rules
> Production-ready analytics rules for Sentinel and Defender XDR — high-fidelity detections with tuned false-positive rates, entity mapping, and response guidance.

### 🎯 Threat Hunting Queries
> Proactive queries to hunt for suspicious activity across the environment:
- **EDR Evasion & Defense Evasion** — BYOVD, ASR bypass, Defender tampering
- **Identity Attacks** — Password spray, MFA fatigue, impossible travel, risky sign-ins
- **Data Exfiltration** — Sensitive file downloads, mass OneDrive/SharePoint access
- **Living-Off-the-Land** — PowerShell abuse, LOLBin misuse, obfuscated commands
- **+ More**

## ⚖️ Detection Rules vs Threat Hunts

Both are needed — they solve different problems.

| | 🚨 Detection Rules | 🔍 Threat Hunts |
| --- | --- | --- |
| **Fires as** | Scheduled alert | Workbook query |
| **Precision** | High — one match = act | Moderate — needs analyst context |
| **Purpose** | Catch known-bad patterns automatically | Proactively find what no one's written a signature for yet |
| **Response** | Immediate, often auto-response | Review, tune, and pivot |
| **Examples** | Break-glass account use, sign-in from IOC, credential file exfil to malicious IP | Suspicious PowerShell scoring, LOLBin abuse, HTTP+Tor download correlation |

- **Detection rules** pinpoint known-bad activity — they demand attention the moment they fire.
- **Threat hunts** surface the noisier activity — a proactive way to find what automation misses and techniques that slip past existing signatures.

---

### 📊 Workbooks & Dashboards

| Workbook | Purpose | When to use |
| --- | --- | --- |
| **🖥️ Security Operations** | Detection overview (alerts by severity, technique, status), EDR Dashboard (AV detections, EDR evasions, Defender sensor health and coverage), ASR Dashboard (blocks vs audits, top rules, audit-only rules ready to enforce) | Daily/weekly proactive review |
| **🚨 Incident Response** | Unified, risk-scored timeline of suspicious activity per device, user, or data exfil path — surfaces activity that never became an alert | Active incident, first response |
| **🔎 Digital Forensics** | Device-scoped timelines: process lineage, file/registry/network activity, persistence inventory | Post-incident deep investigation |

> Workbooks do not replace alert triage. Alerts and incidents should still be investigated — the workbooks support deeper investigation.

---

### 🤖 SOAR Playbooks — *coming soon*

> Logic App workflows for automated response — device isolation, session revocation, IOC block list management, and malicious sender blocking via Microsoft Graph API.

---

## 🛠️ Tools & Platforms

- Microsoft Sentinel
- Microsoft Defender XDR (Endpoint, Identity, Office 365, Cloud Apps)
- KQL (Kusto Query Language)
- Azure Logic Apps

---

## 📚 Standards & Conventions

- **MITRE ATT&CK mapping** on all detections
- **Parameterized time range and device/user filters** on all workbooks
- **Severity scoring** based on confidence and impact

---

## ⚠️ Disclaimer

All queries are provided as-is for educational and defensive purposes. Content is sanitized and does not contain any organization-specific information. Test in a non-production environment before deploying.

---

## 📫 Connect

Feel free to reach out on [LinkedIn](https://www.linkedin.com/in/nguyentimmy/) for questions, feedback, or collaboration.