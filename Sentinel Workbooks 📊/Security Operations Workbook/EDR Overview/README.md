# 🛡️ EDR Overview

The EDR Overview tab of the Security Operations Workbook. It confirms what Defender caught and blocked, and whether the sensors reporting it can be trusted.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `DeviceName` (shown as Hostname, optional; leave empty for all devices), `TimeRange`

| Section | Question it answers |
| --- | --- |
| 🦠 **[AV](AV/)** | *What did antivirus catch — did it clean up, is anyone tampering with the EDR, and is the sensor even reporting?* |
| 🧱 **[ASR](ASR/)** | *What did attack surface reduction block or only audit — and which rules are ready to enforce?* |

Both run passively and in parallel. They watch different failure modes: AV catches known-bad files, ASR blocks risky behavior by policy.

---

## 🦠 AV

| Panel | Visualization | Shows |
|---|---|---|
| 🛡️ Antivirus Detections | Grid | Each detection scored by remediation, execution, threat family and path |
| 🥧 AV Detections by Severity | Pie chart | Detections split by the same risk scoring as Antivirus Detections |
| 🦠 AV Overview Tiles | Tiles | Detections, devices, unique threats, not remediated, ran before caught |
| 📈 AV Detections Over Time | Time chart | Detections per hour for the top 5 threats, everything else grouped as Other |
| 🧬 Top Detected Threats | Grid | Top 10 threats with device count, remediation and first/last seen |
| 🥷 EDR Evasions | Grid | BYOVD drivers, EDR-killer tools, EDR process/service kills, Defender tampering, Safe Mode abuse, log tampering |
| 💓 Defender Health | Grid | Onboarded devices whose sensor isn't Active, with tamper protection state (an empty result means everything is healthy) |
| 📊 Sensor Coverage Tiles | Tiles | Onboarded, active, inactive, impaired devices and coverage % |
| 🟢 Active vs Inactive Sensors | Pie chart | Onboarded devices split by sensor health state |
| 🥧 Onboarding Status | Pie chart | Onboarded vs. devices found by device discovery that aren't onboarded |
| 🧩 Onboarded vs Not Onboarded | Pie chart | VMs sending Azure Monitor heartbeats compared against Defender's onboarded devices |

> 💡 Check **Defender Health** and **Sensor Coverage** first — a device that isn't reporting looks identical to a clean one. After that, a detection marked **Not Remediated** is worth more attention than three clean removals.

Full KQL: [AV/README.md](AV/README.md)

---

## 🧱 ASR

| Panel | Visualization | Shows |
|---|---|---|
| 🛡️ ASR Detections | Grid | Every ASR hit with rule, mode, device, file and initiating process |
| 📊 ASR Overview Tiles | Tiles | Blocks, audits, high-impact blocks, devices and rules triggered |
| 📏 ASR Hits by Rule | Bar chart (or Categorical bar for horizontal) | Hits per rule, split by Block vs Audit |
| 🥧 Block vs Audit | Pie chart | How much is actually blocked vs only audited |
| 🥧 ASR by Severity | Pie chart | Blocks by rule impact |
| 📈 ASR Hits Over Time | Time chart | Hits per hour for the top 5 rules |
| ⚙️ Top Triggering Processes | Grid | Processes that set off ASR rules most |
| 💻 Top Devices | Grid | Devices with the most (high-impact) hits |
| 🎯 Audit-Only Rules | Grid | Rules that only audit, ranked as candidates to switch to Block |

> 💡 The same rule firing on the same device repeatedly is a stronger signal than a one-off hit. A spike across many devices usually means a new campaign — or a legitimate tool that needs an exclusion.

Full KQL: [ASR/README.md](ASR/README.md)

---

## 🧭 Quick reference

| Situation | Where |
| --- | --- |
| A detection came back unremediated | 🦠 AV → Antivirus Detections |
| A sensor is down or tamper protection is off | 🦠 AV → Defender Health |
| Someone may be trying to blind the EDR | 🦠 AV → EDR Evasions |
| Same ASR rule firing across multiple devices | 🧱 ASR → Hits by Rule / Top Devices |
| A legitimate app keeps getting blocked | 🧱 ASR → Top Triggering Processes |
| Deciding which rules to move from Audit to Block | 🧱 ASR → Audit-Only Rules |
| A device shows up repeatedly | 🔍 Incident Response Workbook (Device Investigation) |

---

## 📌 Notes

- Tamper protection can't be read directly in Sentinel (`DeviceTvm*` tables are Defender XDR only), so Defender Health infers it from registry changes. A device that never changed the setting shows **Unknown**.
- AV panels use `AntivirusDetection` events only. `AntivirusReport` re-reports threats that were already detected, so it's left out to avoid double counting.
- The ASR panels exclude the noisy LSASS credential theft rule.