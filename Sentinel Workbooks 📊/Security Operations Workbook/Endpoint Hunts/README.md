## 🎯 Endpoint Hunts

Proactive hunting across the endpoint fleet for activity native detections won't catch. The layer that finds what's hiding, not what already tripped a rule.
Grouped by cadence — daily hunts need same-day eyes; weekly and monthly hunts cover slower-moving or more expensive queries.

🎯 Purpose

This section actively searches for technique-level behavior on endpoints — evasion, staging, unapproved tooling, rare persistence — rather than waiting for a signature or policy to fire.

It's upstream of everything else in this workbook. A hit here becomes the input to Device Compromise Triage once it's confirmed worth escalating.

### Daily

- EDR Evasions
- Highly Executed PowerShell Commands
- Rare Process as Service
- Unapproved Remote Access Tools
- LOLBin Network Egress
- Office Shell Spawn
- BYOVD / Unsigned Driver