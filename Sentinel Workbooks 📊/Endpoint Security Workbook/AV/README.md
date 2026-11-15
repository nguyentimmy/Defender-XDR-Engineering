# AV Health 1.0

Sentinel workbook for Microsoft Defender antivirus detections and sensor health. It shows what AV caught, whether the threat was remediated, and which devices aren't reporting.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `TimeRange`

| Panel | Visualization | Shows |
|---|---|---|
| 🦠 AV Overview Tiles | Tiles | Detections, devices, unique threats, not remediated, ran before caught |
| 📈 AV Detections Over Time | Time chart | Detections per hour for the top 5 threats, everything else grouped as Other |
| 🧬 Top Detected Threats | Grid | Top 10 threats with device count, remediation and first/last seen |
| 🛡️ Antivirus Detections 1.0 | Grid | Each detection scored by remediation, execution, threat family and path |
| 💓 Defender Health | Grid | Onboarded devices whose sensor isn't Active (an empty result means everything is healthy) |
| 📊 Sensor Coverage Tiles | Tiles | Onboarded, active, inactive, impaired devices and coverage % |
| 💤 Stale Devices | Grid | Devices that reported in the last 30 days but have been silent for 7+ days |

**Notes**
- AV panels use `AntivirusDetection` events only. `AntivirusReport` re-reports threats that were already detected, so it's left out to avoid double counting.
- Real-time protection, tamper protection and signature age are in the `DeviceTvm*` tables, which are Defender XDR only and aren't available in Sentinel.

---

## 🦠 AV Overview Tiles
Tiles: Title = `Metric`, Left = `Value`

```kql
let AV = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "AntivirusDetection"
    | extend AF = parse_json(AdditionalFields)
    | extend ThreatName = tostring(AF.ThreatName);
union
    (AV | summarize Value = count() | extend Metric = "🦠 Detections", Order = 1),
    (AV | summarize Value = dcount(DeviceName) | extend Metric = "💻 Devices", Order = 2),
    (AV | summarize Value = dcount(ThreatName) | extend Metric = "🧬 Unique Threats", Order = 3),
    (AV | summarize Value = countif(tostring(AF.WasRemediated) =~ "false") | extend Metric = "❌ Not Remediated", Order = 4),
    (AV | summarize Value = countif(tostring(AF.WasExecutingWhileDetected) =~ "true") | extend Metric = "⚠️ Ran Before Caught", Order = 5)
| sort by Order asc
| project Metric, Value
```

## 📈 AV Detections Over Time
Time chart

```kql
let AV = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "AntivirusDetection"
    | extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName);
let Top = AV | summarize C = count() by ThreatName | top 5 by C | project ThreatName;
AV
| extend Threat = iff(ThreatName in (Top), ThreatName, "Other")
| summarize Detections = count() by bin(TimeGenerated, 1h), Threat
| render timechart
```

## 🧬 Top Detected Threats
Grid: Bar renderer on `Detections`, Date/Time renderer on `FirstSeen` and `LastSeen`

```kql
DeviceEvents
| where TimeGenerated {TimeRange}
| where ActionType == "AntivirusDetection"
| extend AF = parse_json(AdditionalFields)
| summarize Detections = count(), Devices = dcount(DeviceName),
            NotRemediated = countif(tostring(AF.WasRemediated) =~ "false"),
            RanBeforeCaught = countif(tostring(AF.WasExecutingWhileDetected) =~ "true"),
            SamplePath = take_any(FolderPath), SHA256 = take_any(SHA256),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by ThreatName = tostring(AF.ThreatName)
| top 10 by Detections desc
```

## 🛡️ Antivirus Detections 1.0
Grid

```kql
DeviceEvents
| where TimeGenerated {TimeRange}
| where ActionType == "AntivirusDetection"
| extend Fields = parse_json(AdditionalFields)
| extend
    ThreatName = tostring(Fields.ThreatName),
    WasRemediated = tostring(Fields.WasRemediated),
    WasExecutingWhileDetected = tostring(Fields.WasExecutingWhileDetected),
    RemediationAction = tostring(Fields.RemediationAction)
| where isnotempty(ThreatName)
| extend
    NotRemediated = WasRemediated =~ "false" or RemediationAction has_any ("Allowed", "NotRemediated", "Failed"),
    WasRunning = WasExecutingWhileDetected =~ "true",
    IsHighImpactFamily = ThreatName has_any (
        "Ransom", "Backdoor", "Mimikatz", "Rootkit", "HackTool", "VirTool", "Exploit",
        "Cobalt", "Meterpreter", "Sliver", "Emotet", "Qakbot", "AsyncRAT",
        "RedLine", "Lumma", "Vidar", "Amadey"
    ),
    RanFromSuspiciousPath = FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Users\\Public\\",
        "\\ProgramData\\", "\\PerfLogs\\", "/tmp/", "/dev/shm/", "/var/tmp/"
    )
| extend RiskScore = toint(3 + iff(NotRemediated, 4, 0) + iff(WasRunning, 3, 0)
                             + iff(IsHighImpactFamily, 3, 0) + iff(RanFromSuspiciousPath, 1, 0))
| extend Severity = case(RiskScore >= 10, "🔴 Critical", RiskScore >= 7, "🟠 High", RiskScore >= 5, "🟡 Medium", "🟢 Low")
| extend Action = case(
    NotRemediated, "❌ Not Remediated",
    WasRemediated =~ "true", "✅ Remediated / Blocked",
    isnotempty(RemediationAction), RemediationAction,
    "❔ Unknown")
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Hits = count(),
    Files = make_set(FileName, 5),
    Paths = make_set(FolderPath, 5)
    by Severity, RiskScore, ThreatName, DeviceName, Account = InitiatingProcessAccountName,
       Action, InitiatingProcess = InitiatingProcessFileName, SHA256,
       WasRemediated, WasExecutingWhileDetected, RemediationAction,
       NotRemediated, WasRunning, IsHighImpactFamily, RanFromSuspiciousPath
| project
    TimeGenerated = FirstSeen, Severity, RiskScore, Hits, ThreatName,
    DeviceName, Account, Action,
    Files = strcat_array(Files, ", "), Paths = strcat_array(Paths, ", "),
    InitiatingProcess, SHA256,
    WasRemediated, WasExecutingWhileDetected, RemediationAction,
    NotRemediated, WasRunning, IsHighImpactFamily, RanFromSuspiciousPath,
    LastSeen
| sort by RiskScore desc, TimeGenerated desc
```

**Risk score:** base 3, plus 4 if not remediated, 3 if it was running, 3 for a high-impact family and 1 for a suspicious path. 10+ = Critical, 7+ = High, 5+ = Medium.

## 💓 Defender Health
Grid

```kql
DeviceInfo
| where TimeGenerated {TimeRange}
| summarize arg_max(TimeGenerated, OnboardingStatus, SensorHealthState, OSPlatform) by DeviceName, DeviceId
| where OnboardingStatus == "Onboarded"
| where SensorHealthState !in~ ("Active", "")
| extend Severity = case(
    SensorHealthState has_any ("Inactive", "Misconfigured"), "🔴 Critical",
    SensorHealthState has "ImpairedCommunication", "🟠 High",
    "🟡 Medium"
)
| project
    LastSeen = TimeGenerated,
    Severity,
    DeviceName,
    OSPlatform,
    SensorHealthState,
    OnboardingStatus,
    DeviceId
| sort by Severity asc, LastSeen asc
```

## 📊 Sensor Coverage Tiles
Tiles: Title = `Metric`, Left = `Value`

```kql
let H = DeviceInfo
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, OnboardingStatus, SensorHealthState) by DeviceId
    | where OnboardingStatus == "Onboarded";
let Total = toscalar(H | count);
union
    (H | summarize Value = count() | extend Metric = "💻 Onboarded", Order = 1),
    (H | summarize Value = countif(SensorHealthState == "Active") | extend Metric = "✅ Active", Order = 2),
    (H | summarize Value = countif(SensorHealthState == "Inactive") | extend Metric = "⛔ Inactive", Order = 3),
    (H | summarize Value = countif(SensorHealthState has_any ("Impaired", "Misconfigured")) | extend Metric = "⚠️ Impaired", Order = 4),
    (H | summarize Value = tolong(round(100.0 * countif(SensorHealthState == "Active") / max_of(Total, 1))) | extend Metric = "📊 Coverage %", Order = 5)
| sort by Order asc
| project Metric, Value
```

## 💤 Stale Devices
Grid (fixed 30-day lookback, ignores `TimeRange`)

```kql
DeviceInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, OSPlatform, SensorHealthState, ClientVersion, PublicIP) by DeviceName
| where TimeGenerated < ago(7d)
| extend DaysSilent = datetime_diff("day", now(), TimeGenerated)
| project LastSeen = TimeGenerated, DaysSilent, DeviceName, OSPlatform, SensorHealthState, ClientVersion, PublicIP
| sort by DaysSilent desc
```
