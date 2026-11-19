# 🎯 Threat Hunt Overview

Proactive threat hunting workbooks for Microsoft Sentinel and Defender XDR. **Daily Hunts** covers routine hunts for known attacker techniques on devices. **AI Autonomous Hunts** tracks LLM usage and the machine-speed activity of AI-driven attacks.

🔎 The hunts are built to surface the noisier, lower-severity activity that alerts often filter out, and to catch threats that may go undetected by existing detections.

> ⚠️ **Disclaimer:** These workbooks are for hunting and triage visibility. They do not replace alert triage. Alerts and incidents should still be investigated for deeper analysis.

---

## 📁 Contents

| Folder | Workbook | Focus |
|---|---|---|
| 📅 [Daily Hunts](Daily%20Hunts/README.md) | Daily Hunts | Known attacker techniques on devices |
| 🤖 [AI Autonomous Hunts](AI%20Autonomous%20Hunts/README.md) | AI & Autonomous Threats | LLM API usage, offensive AI tooling and machine-speed attack activity |

---

## 📅 Daily Hunts

Routine hunts to run daily or at the start of a shift. Each hunt is its own table.

| Section | Hunts |
|---|---|
| 💻 **Device Hunts** | HTTP + Tor, LOLBin Execution, Remote File Drops, Sensitive Config Downloads, Webshell Activity, EDR Evasions, Highly Executed PowerShell from External Sources, Rare Process As Service, Unapproved Remote Access Tools |

---

## 🤖 AI & Autonomous Threats

Covers both places an AI attack can show up: agents running **on your devices**, and agents running **on the attacker's infrastructure** that you only see by the speed and volume of what reaches you.

| Section | Panels |
|---|---|
| 🧠 **LLM Usage** | Overview Tiles, LLM API Calls Over Time, LLM Calls by Provider, Top LLM API Callers, Unsanctioned LLM Activity |
| 🕵️ **On-Device Agents** | LLM-Driven Offensive Agent, Recon Toolchain Burst, AI Agent Framework Activity, Local LLM Runtimes |
| 🌐 **Inbound Machine-Speed Activity** | Inbound Scan & Sweep Bursts, Machine-Speed Logon Failures, Web Request Bursts, WAF Request Bursts |
| ⚡ **Post-Foothold** | Machine-Speed Discovery |

---

## 🎛️ Parameters

| Parameter | Display Name | Used In |
|---|---|---|
| `TimeRange` | Time Range | Both workbooks |
| `DeviceName` | Hostname | Both workbooks |

Hostname is optional. Leave it empty to search all devices.

---

## 🔄 Workflow

1. 📅 **Daily Hunts:** run at the start of a shift and work through each Device Hunt.
2. 🤖 **AI & Autonomous Threats:** check the overview tiles. Then review any 🔴 **Critical** or 🟠 **High** rows in On-Device Agents, Inbound Machine-Speed Activity and Post-Foothold.
3. 🔍 **Pivot:** set Hostname to a flagged device, then open the Device Compromise IR workbook for a full timeline.
4. 🚨 **Escalate:** confirmed findings become incidents, and repeat findings become analytic rules.

---

## 📝 Notes

- 🛠️ Tuning details for each workbook, such as allowlists, thresholds and sanctioned AI apps, are in its own README.
- 🧪 Approved pentest and red team devices will show up in several hunts. Exclude them by hostname or device tag.
- 📊 Panels that aggregate work as scheduled Sentinel analytic rules rather than Defender custom detections.