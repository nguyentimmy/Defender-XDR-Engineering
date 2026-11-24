# 🚨 Alert Dashboard

The **Alert Dashboard** group of the Detection Dashboard tab: an at-a-glance view of everything that alerted, built on the Sentinel `SecurityAlert` table. The [Incident Dashboard](Incident%20Dashboard.md) group sits below it in the same tab.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `DeviceName` (shown as Hostname), `UserName`, `TimeRange`. Leave Hostname and UserName empty to see every alert.

| Panel | Visualization | Shows |
|---|---|---|
| 🚨 Alerts | Grid | Searchable alert table with status, severity, device, account, files, commands, IOCs and SHA256 |
| 🥧 Detection by Severity | Pie chart | Alert count by severity |
| 🎯 Detections by Tactic | Bar chart | Which attack stages are being detected |
| ⚙️ Processes On Device | Time chart | Process activity over time for the top 5 processes |
| 📂 Alert Status | Pie chart | New vs. In Progress vs. Resolved |
| 🔟 Top 10 Alert Types | Grid | Noisiest alerts with severity, product, tactics, devices, users and first/last seen |
| 📈 Alerts Over Time by Severity | Time chart | Alert volume trend by severity |

**Notes**
- Uses `SecurityAlert` because `AlertInfo` / `AlertEvidence` are empty in Sentinel unless streamed separately.
- Alerts are deduplicated by `SystemAlertId`, so each alert counts once at its latest status.
- `UserName` matches a full UPN or just the name part (e.g. `jdoe`). A very short value like `admin` will match a lot.

---

## 🚨 Alerts
Grid. Sorted by severity, then newest first.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UserSearch = tolower(trim(" ", "{UserName}"));
let UserLocal = tostring(split(UserSearch, "@")[0]);
SecurityAlert
| where TimeGenerated {TimeRange}
| where ProductName has_any ("Defender", "Microsoft 365", "MDATP")
    or ProviderName has_any ("MDATP", "Microsoft 365 Defender", "Microsoft XDR")
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| extend Ents = parse_json(Entities)
| mv-apply E = Ents on (
    extend T = tolower(tostring(E.Type))
    | summarize
        Hosts = make_set_if(coalesce(tostring(E.HostName), tostring(E.FQDN)), T == "host", 5),
        Accounts = make_set_if(iff(isnotempty(tostring(E.UPNSuffix)), strcat(tostring(E.Name), "@", tostring(E.UPNSuffix)), tostring(E.Name)), T == "account", 5),
        Files = make_set_if(strcat(tostring(E.Directory), "/", tostring(E.Name)), T == "file", 5),
        Commands = make_set_if(substring(tostring(E.CommandLine), 0, 200), T == "process" and isnotempty(tostring(E.CommandLine)), 3),
        Hashes = make_set_if(tostring(E.Value), T == "filehash" and tostring(E.Algorithm) =~ "SHA256", 5),
        IPs = make_set_if(tostring(E.Address), T == "ip", 5),
        Urls = make_set_if(tostring(E.Url), T == "url", 5)
)
| extend Device = iff(array_length(Hosts) > 0, strcat_array(Hosts, ", "), CompromisedEntity)
| where isempty(TargetDevice) or Device has TargetDevice or CompromisedEntity has TargetDevice
| where isempty(UserSearch)
    or tolower(strcat_array(Accounts, ",")) contains UserLocal
    or tolower(Entities) contains UserSearch
| extend SevOrder = case(AlertSeverity =~ "High", 1, AlertSeverity =~ "Medium", 2, AlertSeverity =~ "Low", 3, 4)
| extend ThreatFamily = tostring(parse_json(ExtendedProperties).ThreatFamily)
| project
    TimeGenerated,
    Status,
    Severity = case(AlertSeverity =~ "High", "🔴 High", AlertSeverity =~ "Medium", "🟠 Medium",
                    AlertSeverity =~ "Low", "🟡 Low", "⚪ Informational"),
    Title = AlertName,
    Description = substring(Description, 0, 250),
    Device,
    Account = strcat_array(Accounts, ", "),
    Files = replace_string(strcat_array(Files, ", "), "//", "/"),
    Commands = strcat_array(Commands, " || "),
    IOCs = strcat_array(array_concat(Urls, IPs), ", "),
    SHA256 = strcat_array(Hashes, ", "),
    ThreatFamily,
    SystemAlertId,
    Category = Tactics,
    SevOrder
| sort by SevOrder asc, TimeGenerated desc
| project-away SevOrder
```

## 🥧 Detection by Severity
Pie chart. Series colors: High red, Medium orange, Low yellow, Informational gray.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UserSearch = tolower(trim(" ", "{UserName}"));
let UserLocal = tostring(split(UserSearch, "@")[0]);
let A = SecurityAlert
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | where isempty(TargetDevice) or CompromisedEntity has TargetDevice or Entities has TargetDevice
    | where isempty(UserSearch)
        or tolower(Entities) contains UserSearch
        or tolower(Entities) contains strcat('"name":"', UserLocal, '"')
        or tolower(CompromisedEntity) contains UserLocal;
A
| extend Severity = case(AlertSeverity =~ "High", "🔴 High", AlertSeverity =~ "Medium", "🟠 Medium",
                         AlertSeverity =~ "Low", "🟡 Low", "⚪ Informational")
| summarize Alerts = count() by Severity
| sort by Alerts desc
```

## 🎯 Detections by Tactic
Bar chart. Alerts with several tactics count once toward each.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UserSearch = tolower(trim(" ", "{UserName}"));
let UserLocal = tostring(split(UserSearch, "@")[0]);
let A = SecurityAlert
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | where isempty(TargetDevice) or CompromisedEntity has TargetDevice or Entities has TargetDevice
    | where isempty(UserSearch)
        or tolower(Entities) contains UserSearch
        or tolower(Entities) contains strcat('"name":"', UserLocal, '"')
        or tolower(CompromisedEntity) contains UserLocal;
A
| mv-expand Tactic = split(Tactics, ",") to typeof(string)
| extend Tactic = iff(isempty(trim(" ", Tactic)), "Unknown", trim(" ", Tactic))
| summarize Detections = count() by Tactic
| sort by Detections desc
| render barchart
```

## ⚙️ Processes On Device
Time chart. Top 5 processes by run count, everything else grouped as Other.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let P = DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice;
let Top = P | summarize C = count() by FileName | top 5 by C | project FileName;
P
| extend Process = iff(FileName in (Top), FileName, "Other")
| summarize Runs = count() by bin(TimeGenerated, 1h), Process
| render timechart
```

## 📂 Alert Status
Pie chart. Colors: New red/orange, InProgress yellow, Resolved green.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UserSearch = tolower(trim(" ", "{UserName}"));
let UserLocal = tostring(split(UserSearch, "@")[0]);
let A = SecurityAlert
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | where isempty(TargetDevice) or CompromisedEntity has TargetDevice or Entities has TargetDevice
    | where isempty(UserSearch)
        or tolower(Entities) contains UserSearch
        or tolower(Entities) contains strcat('"name":"', UserLocal, '"')
        or tolower(CompromisedEntity) contains UserLocal;
A
| summarize Alerts = count() by Status
```

## 🔟 Top 10 Alert Types
Grid. Bar renderer on `Count`, Thresholds on `Severity`, Date/Time on `FirstSeen` and `LastSeen`.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UserSearch = tolower(trim(" ", "{UserName}"));
let UserLocal = tostring(split(UserSearch, "@")[0]);
let A = SecurityAlert
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | where isempty(TargetDevice) or CompromisedEntity has TargetDevice or Entities has TargetDevice
    | where isempty(UserSearch)
        or tolower(Entities) contains UserSearch
        or tolower(Entities) contains strcat('"name":"', UserLocal, '"')
        or tolower(CompromisedEntity) contains UserLocal;
A
| extend SevRank = case(AlertSeverity == "High", 4, AlertSeverity == "Medium", 3, AlertSeverity == "Low", 2, 1),
         Users = extract_all(@'"UserPrincipalName":"([^"]+)"', Entities)
| summarize Count = count(),
            SevRank = max(SevRank),
            Devices = dcount(CompromisedEntity),
            Users = make_set(Users, 10),
            Product = take_any(ProductName),
            Tactics = make_set(Tactics, 5),
            Status = make_set(Status, 3),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by AlertName
| sort by Count desc
| take 10
| extend Severity = case(SevRank == 4, "High", SevRank == 3, "Medium", SevRank == 2, "Low", "Informational"),
         Users = strcat_array(Users, ", "),
         Tactics = strcat_array(Tactics, ", "),
         Status = strcat_array(Status, ", ")
| project AlertName, Count, Severity, Product, Tactics, Devices, Users, Status, FirstSeen, LastSeen
```

## 📈 Alerts Over Time by Severity
Time chart. Same severity colors as the pie. Change `1h` to `1d` for ranges over about 3 days.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UserSearch = tolower(trim(" ", "{UserName}"));
let UserLocal = tostring(split(UserSearch, "@")[0]);
let A = SecurityAlert
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | where isempty(TargetDevice) or CompromisedEntity has TargetDevice or Entities has TargetDevice
    | where isempty(UserSearch)
        or tolower(Entities) contains UserSearch
        or tolower(Entities) contains strcat('"name":"', UserLocal, '"')
        or tolower(CompromisedEntity) contains UserLocal;
A
| summarize Alerts = count() by bin(TimeGenerated, 1h), AlertSeverity
| render timechart
```