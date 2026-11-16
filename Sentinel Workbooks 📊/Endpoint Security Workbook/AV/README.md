# EDR Dashboard 1.0

Sentinel workbook for Microsoft Defender antivirus detections, EDR tampering and sensor health. It shows what AV caught, whether the threat was remediated, attempts to blind the EDR, and which devices aren't reporting.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `DeviceName` (shown as Hostname, optional; leave empty for all devices), `TimeRange`

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

**Notes**
- AV panels use `AntivirusDetection` events only. `AntivirusReport` re-reports threats that were already detected, so it's left out to avoid double counting.
- Real-time protection, tamper protection and signature age are in the `DeviceTvm*` tables, which are Defender XDR only and aren't available in Sentinel.

---

## 🛡️ Antivirus Detections
Grid

```kql
let TargetDevice = trim(" ", "{DeviceName}");
DeviceEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
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

## 🥧 AV Detections by Severity
Pie chart. Series colors: Critical red, High orange, Medium yellow, Low green.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
DeviceEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "AntivirusDetection"
| extend F = parse_json(AdditionalFields)
| extend ThreatName = tostring(F.ThreatName),
         WasRemediated = tostring(F.WasRemediated),
         RemediationAction = tostring(F.RemediationAction)
| where isnotempty(ThreatName)
| extend
    NotRemediated = WasRemediated =~ "false" or RemediationAction has_any ("Allowed", "NotRemediated", "Failed"),
    WasRunning = tostring(F.WasExecutingWhileDetected) =~ "true",
    IsHighImpactFamily = ThreatName has_any (
        "Ransom", "Backdoor", "Mimikatz", "Rootkit", "HackTool", "VirTool", "Exploit",
        "Cobalt", "Meterpreter", "Sliver", "Emotet", "Qakbot", "AsyncRAT",
        "RedLine", "Lumma", "Vidar", "Amadey"),
    RanFromSuspiciousPath = FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Users\\Public\\",
        "\\ProgramData\\", "\\PerfLogs\\", "/tmp/", "/dev/shm/", "/var/tmp/")
| extend RiskScore = 3 + iff(NotRemediated, 4, 0) + iff(WasRunning, 3, 0)
                       + iff(IsHighImpactFamily, 3, 0) + iff(RanFromSuspiciousPath, 1, 0)
| extend Severity = case(RiskScore >= 10, "Critical", RiskScore >= 7, "High", RiskScore >= 5, "Medium", "Low")
| summarize Detections = count() by Severity
```

## 🦠 AV Overview Tiles
Tiles: Title = `Metric`, Left = `Value`

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let AV = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
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
let TargetDevice = trim(" ", "{DeviceName}");
let AV = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
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
let TargetDevice = trim(" ", "{DeviceName}");
DeviceEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
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

## 🥷 EDR Evasions
Grid

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let EdrProcesses = dynamic([
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe",
    "CSFalconService.exe", "CSFalconContainer.exe",
    "SentinelAgent.exe", "SentinelServiceHost.exe", "SentinelStaticEngine.exe",
    "cb.exe", "RepMgr.exe", "RepUx.exe", "CylanceSvc.exe",
    "SophosHealth.exe", "SAVService.exe", "McShield.exe", "mfemms.exe",
    "ccSvcHst.exe", "SmcGui.exe", "xagt.exe", "TmCCSF.exe", "elastic-agent.exe"
]);
let EdrServices = dynamic([
    "WinDefend", "Sense", "WdNisSvc", "SecurityHealthService", "wscsvc",
    "CSFalconService", "SentinelAgent", "CbDefense", "CylanceSvc",
    "SAVService", "McAfeeFramework", "SepMasterService", "xagt"
]);
let VulnerableDrivers = dynamic([
    "rtcore64.sys", "rtkvhd64.sys", "gdrv.sys", "iqvw64e.sys", "dbutil_2_3.sys",
    "mhyprot2.sys", "procexp152.sys", "aswarpot.sys", "truesight.sys",
    "viragt64.sys", "kprocesshacker.sys", "gmer64.sys", "nvflash.sys",
    "elrawdsk.sys", "atillk64.sys", "speedfan.sys", "winio64.sys"
]);
let EdrKillerTools = dynamic([
    "aukill.exe", "terminator.exe", "edrkillshifter.exe", "edrsilencer.exe",
    "backstab.exe", "edrsandblast.exe", "gmer.exe", "processhacker.exe",
    "pchunter64.exe", "kdu.exe", "spyboy.exe", "zam64.sys"
]);
union isfuzzy=true
// 1. BYOVD - vulnerable signed driver loaded
(
    DeviceImageLoadEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName has_any (VulnerableDrivers)
    | extend Technique = "🔴 BYOVD Vulnerable Driver Load",
             RiskScore = 9,
             Detail = substring(strcat("Driver: ", FileName, " | Path: ", FolderPath, " | By: ", InitiatingProcessFileName), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail
),
// 1b. BYOVD - vulnerable driver dropped
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName has_any (VulnerableDrivers)
    | where ActionType in ("FileCreated", "FileModified")
    | extend Technique = "🔴 BYOVD Vulnerable Driver Dropped",
             RiskScore = 9,
             Detail = substring(strcat("Driver: ", FileName, " | Path: ", FolderPath, " | By: ", InitiatingProcessFileName), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail
),
// 2. EDR-killer tooling
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where tolower(FileName) in~ (EdrKillerTools)
        or (CmdArgs has_any (EdrKillerTools) and CmdArgs has_any (EdrProcesses))
    | extend Technique = "🔴 EDR-Killer Tool Execution",
             RiskScore = 10,
             Detail = substring(strcat(FileName, " | ", CmdArgs, " | Path: ", FolderPath), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 3. EDR process termination
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ ("taskkill.exe", "tskill.exe", "wmic.exe", "powershell.exe", "pwsh.exe", "pskill.exe", "pskill64.exe")
    | where CmdArgs has_any (EdrProcesses)
    | where CmdArgs has_any ("/f", "/im", "/pid", "Stop-Process", "kill", "terminate", "-Force")
    | extend Technique = "🔴 EDR Process Termination",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 4. EDR service stop / disable
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ ("sc.exe", "net.exe", "net1.exe", "powershell.exe", "pwsh.exe", "reg.exe")
    | where CmdArgs has_any (EdrServices)
    | where CmdArgs has_any ("stop", "delete", "disabled", "start= disabled", "Stop-Service", "Set-Service", "config", "Remove-Service")
    | extend Technique = "🔴 EDR Service Stop / Disable",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 5. Defender tampering
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any (
        "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
        "DisableIOAVProtection", "DisableScriptScanning",
        "DisableArchiveScanning", "DisableBlockAtFirstSeen",
        "DisableAntiSpyware", "DisableAntiVirus",
        "TamperProtection", "MpEnablePus",
        "Add-MpPreference -ExclusionPath", "Add-MpPreference -ExclusionProcess",
        "Add-MpPreference -ExclusionExtension",
        "AmsiScanBuffer", "amsiInitFailed", "AmsiUtils"
    )
    | extend IsExclusion = CmdArgs has "ExclusionPath" or CmdArgs has "ExclusionProcess" or CmdArgs has "ExclusionExtension"
    | extend Technique = iff(IsExclusion, "🟠 Defender Exclusion Added", "🔴 Defender Protection Disabled"),
             RiskScore = iff(IsExclusion, 7, 9),
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 6. Safe Mode abuse
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("bcdedit", "safeboot", "bootstatuspolicy")
    | where CmdArgs has_any ("/set", "safeboot network", "safeboot minimal", "-set")
    | extend Technique = "🔴 Safe Mode Boot Configuration",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 7. Event log / telemetry tampering
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any (
        "wevtutil cl", "wevtutil sl", "Clear-EventLog", "Remove-EventLog",
        "auditpol /clear", "auditpol /remove", "auditpol /set",
        "fsutil usn deletejournal", "EtwEventWrite", "PatchTraceLogging"
    )
    | extend Technique = "🔴 Event Log / ETW Tampering",
             RiskScore = 9,
             Detail = substring(strcat(FileName, " | ", CmdArgs), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail
),
// 8. Native Defender tamper events
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in (
        "AntivirusDisabled", "AntivirusConfigurationChange",
        "TamperingAttempt", "SecurityLogCleared",
        "AntivirusScanCancelled", "AntivirusEmergencyUpdatesInstalled"
    )
    | extend Technique = "🔴 Native Defender Tamper Event",
             RiskScore = 9,
             Detail = substring(strcat(ActionType, " | ", tostring(AdditionalFields)), 0, 300)
    | project TimeGenerated, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail
)
| extend Severity = case(
    RiskScore >= 9, "🔴 Critical",
    RiskScore >= 7, "🟠 High",
    "🟡 Medium"
)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    OccurrenceCount = count(),
    Details = make_set(Detail, 3)
    by Technique, Severity, RiskScore, DeviceName, AccountName, ProcessName
| project
    FirstSeen,
    Severity,
    OccurrenceCount,
    Technique,
    DeviceName,
    AccountName,
    ProcessName,
    Details,
    RiskScore,
    LastSeen
| sort by RiskScore desc, OccurrenceCount desc
```

**Note:** `AntivirusScanCancelled` and `AntivirusEmergencyUpdatesInstalled` also happen during normal operation. Remove them from section 8 if that row gets noisy.

## 💓 Defender Health
Grid

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let TP = DeviceRegistryEvents
    | where TimeGenerated > ago(90d)
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where RegistryKey has @"Microsoft\Windows Defender\Features"
    | where RegistryValueName == "TamperProtection"
    | summarize arg_max(TimeGenerated, RegistryValueData) by DeviceId
    | project DeviceId, TPValue = RegistryValueData, TPChanged = TimeGenerated;
DeviceInfo
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| summarize arg_max(TimeGenerated, OnboardingStatus, SensorHealthState, OSPlatform) by DeviceName, DeviceId
| where OnboardingStatus == "Onboarded"
| where SensorHealthState !in~ ("Active", "")
| join kind=leftouter TP on DeviceId
| extend TamperProtection = case(
    TPValue == "5", "✅ On",
    TPValue in ("0", "4"), "⛔ Off",
    OSPlatform !startswith "Windows", "N/A",
    "❔ Unknown")
| extend Severity = case(
    SensorHealthState has_any ("Inactive", "Misconfigured") or TamperProtection == "⛔ Off", "🔴 Critical",
    SensorHealthState has "ImpairedCommunication", "🟠 High",
    "🟡 Medium"
)
| project LastSeen = TimeGenerated, Severity, DeviceName, OSPlatform, SensorHealthState,
          TamperProtection, TPChanged, OnboardingStatus, DeviceId
| sort by Severity asc, LastSeen asc
```

`TamperProtection` comes from registry changes in the last 90 days. A device that hasn't changed the setting shows **Unknown**.

## 📊 Sensor Coverage Tiles
Tiles: Title = `Metric`, Left = `Value`

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let H = DeviceInfo
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
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

## 🟢 Active vs Inactive Sensors
Pie chart. Colors: Active green, Inactive red, Impaired orange, Unknown gray.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
DeviceInfo
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| summarize arg_max(TimeGenerated, OnboardingStatus, SensorHealthState) by DeviceId
| where OnboardingStatus == "Onboarded"
| extend Status = case(
    SensorHealthState == "Active", "✅ Active",
    SensorHealthState == "Inactive", "⛔ Inactive",
    SensorHealthState has_any ("Impaired", "Misconfigured"), "⚠️ Impaired",
    "❔ Unknown")
| summarize Devices = count() by Status
```

## 🥧 Onboarding Status
Pie chart. Colors: Onboarded green, Not Onboarded orange, Unsupported red, Insufficient Info gray.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
DeviceInfo
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| summarize arg_max(TimeGenerated, OnboardingStatus) by DeviceId
| extend Status = case(
    OnboardingStatus == "Onboarded", "✅ Onboarded",
    OnboardingStatus == "Can be onboarded", "⚠️ Not Onboarded",
    OnboardingStatus == "Unsupported", "⛔ Unsupported",
    "❔ Insufficient Info")
| summarize Devices = count() by Status
```

"Not Onboarded" only shows devices that Defender's device discovery found on the network. With discovery off, or nothing unmanaged on the network, this pie is all Onboarded.

## 🧩 Onboarded vs Not Onboarded
Pie chart. Colors: Onboarded green, Not Onboarded orange.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let MDE = DeviceInfo
    | where TimeGenerated > ago(30d)
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where OnboardingStatus == "Onboarded"
    | summarize by Name = tolower(tostring(split(DeviceName, ".")[0]));
Heartbeat
| where TimeGenerated > ago(30d)
| where isempty(TargetDevice) or Computer has TargetDevice
| summarize arg_max(TimeGenerated, OSType) by Name = tolower(tostring(split(Computer, ".")[0]))
| extend Status = iff(Name in (MDE), "✅ Onboarded", "⚠️ Not Onboarded")
| summarize Devices = count() by Status
```

Requires the Azure Monitor Agent on the VMs. Devices are matched on short hostname, since Defender sometimes reports the full domain name. VMs without the agent won't appear.
