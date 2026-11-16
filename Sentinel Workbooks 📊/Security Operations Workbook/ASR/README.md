# ASR Dashboard 1.0

Sentinel workbook for Microsoft Defender Attack Surface Reduction (ASR) rules. It shows what ASR blocked, what it only audited, and which rules are ready to move from Audit to Block.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `DeviceName` (shown as Hostname, optional; leave empty for all devices), `TimeRange`

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

**Notes**
- Covers both Block and Audit events. `Rule` is the ASR action type without the `Asr` prefix and the `Blocked`/`Audited` suffix.
- Severity is set by rule impact: High = ransomware, email/Office child processes, script downloads, PsExec/WMI, vulnerable drivers, WMI persistence, Safe Mode reboot. Medium = injection, macros, obfuscated scripts, untrusted executables/USB. Everything else is Low.
- The LSASS credential theft rule is excluded because it's very noisy. Remove that line if you want it back.
- Every query starts with the same shared block (parameters, severity lists, and the `ASR` base table).

---

## 🛡️ ASR Detections
Grid. Thresholds on `Severity` (High red, Medium orange, Low yellow), Bar renderer on `Hits`.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Hits = count()
    by Severity, Mode, Rule, DeviceName, Account = InitiatingProcessAccountName,
       FileName, FolderPath, InitiatingProcess = InitiatingProcessFileName,
       InitiatingProcessCmd = substring(InitiatingProcessCommandLine, 0, 300), SHA256
| extend SevOrder = case(Severity == "High", 1, Severity == "Medium", 2, 3)
| project TimeGenerated = FirstSeen, Severity, Hits, Mode, Rule, DeviceName, Account,
          FileName, FolderPath, InitiatingProcess, InitiatingProcessCmd, SHA256, LastSeen, SevOrder
| sort by SevOrder asc, Hits desc
| project-away SevOrder
```

Block = the action was stopped. Audit = the rule would have stopped it but is only in audit mode.

## 📊 ASR Overview Tiles
Tiles: Title = `Metric`, Left = `Value`.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
union
    (ASR | where Mode == "Block" | summarize Value = count() | extend Metric = "🛑 Blocks", Order = 1),
    (ASR | where Mode == "Audit" | summarize Value = count() | extend Metric = "👁️ Audits", Order = 2),
    (ASR | where Mode == "Block" and Severity == "High" | summarize Value = count() | extend Metric = "🔴 High-Impact Blocks", Order = 3),
    (ASR | summarize Value = dcount(DeviceName) | extend Metric = "💻 Devices", Order = 4),
    (ASR | summarize Value = dcount(Rule) | extend Metric = "📏 Rules Triggered", Order = 5)
| sort by Order asc
| project Metric, Value
```

## 📏 ASR Hits by Rule
Bar chart (or Categorical bar for horizontal). Series colors: Block red, Audit gray.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| summarize Hits = count() by Rule, Mode
| order by Hits desc
```

The most useful chart here: it shows which rules fire most and whether they're blocking or just auditing.

## 🥧 Block vs Audit
Pie chart. Colors: Block red, Audit gray.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| summarize Hits = count() by Mode
```

## 🥧 ASR by Severity
Pie chart. Colors: High red, Medium orange, Low yellow.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| where Mode == "Block"
| summarize Hits = count() by Severity
```

Blocks only, so audits don't inflate it.

## 📈 ASR Hits Over Time
Time chart.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
let Top = ASR | summarize C = count() by Rule | top 5 by C | project Rule;
ASR
| extend Rule = iff(Rule in (Top), Rule, "Other")
| summarize Hits = count() by bin(TimeGenerated, 1h), Rule
| render timechart
```

Top 5 rules, everything else grouped as Other. Change `1h` to `1d` for ranges over about 3 days.

## ⚙️ Top Triggering Processes
Grid. Bar renderer on `Hits`.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| summarize Hits = count(), Devices = dcount(DeviceName), Rules = make_set(Rule, 5),
            Modes = make_set(Mode, 2), SamplePath = take_any(InitiatingProcessFolderPath),
            LastSeen = max(TimeGenerated)
    by InitiatingProcess = InitiatingProcessFileName, InitiatingProcessSHA256
| extend Rules = strcat_array(Rules, ", "), Modes = strcat_array(Modes, ", ")
| top 15 by Hits desc
```

The processes setting off ASR rules. Use it to spot attack tooling, or legitimate apps that need an exclusion.

## 💻 Top Devices
Grid. Bar renderer on `Hits`.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| summarize Hits = count(), Blocks = countif(Mode == "Block"), HighBlocks = countif(Mode == "Block" and Severity == "High"),
            Rules = make_set(Rule, 5), LastSeen = max(TimeGenerated)
    by DeviceName
| extend Rules = strcat_array(Rules, ", ")
| sort by HighBlocks desc, Hits desc
| take 15
```

Devices with repeated high-impact blocks are worth a run through Device Compromise Triage.

## 🎯 Audit-Only Rules
Grid.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let HighRules = dynamic(["Ransomware", "ExecutableEmailContent", "OfficeChildProcess", "ScriptExecutableDownload",
    "PsexecWmiChildProcess", "VulnerableSignedDriver", "PersistenceThroughWmi", "SafeModeReboot"]);
let MedRules = dynamic(["OfficeProcessInjection", "ExecutableOfficeContent", "OfficeMacroWin32ApiCalls", "ObfuscatedScript",
    "UntrustedExecutable", "UntrustedUsbProcess", "AdobeReaderChildProcess", "OfficeCommAppChildProcess", "ImpersonatedSystemTools"]);
let ASR = DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType startswith "Asr"
    | where ActionType !startswith "AsrLsassCredentialTheft"
    | extend Mode = iff(ActionType endswith "Audited", "Audit", "Block"),
             Rule = replace_regex(ActionType, @"^Asr|(Blocked|Audited)$", "")
    | extend Severity = case(Rule in (HighRules), "High", Rule in (MedRules), "Medium", "Low");
ASR
| summarize Audits = countif(Mode == "Audit"), Blocks = countif(Mode == "Block"),
            Devices = dcount(DeviceName), Processes = dcount(InitiatingProcessFileName),
            TopProcesses = make_set(InitiatingProcessFileName, 5), LastSeen = max(TimeGenerated)
    by Rule, Severity
| where Audits > 0 and Blocks == 0
| extend TopProcesses = strcat_array(TopProcesses, ", ")
| sort by Severity asc, Audits desc
```

Rules that are only auditing. Few processes and few devices usually means the rule is safe to switch to Block. Many legitimate processes means it needs exclusions first.
