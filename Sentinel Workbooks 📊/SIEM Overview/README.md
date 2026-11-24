# 📡 SIEM Overview

A Microsoft Sentinel workbook for the health of the SIEM itself: how much data is coming in and what it costs, whether connectors and agents are still sending, how late data arrives, and whether analytics and automation rules are running. If a table goes quiet, every detection built on it goes quiet too, so this is the view that tells you how far to trust the others.

| Panel | Visualization | Shows |
|---|---|---|
| 📊 Ingestion Summary | Tiles | GB today, 7-day daily average, last 30 days, estimated monthly cost, free data, active tables |
| 📈 Daily Ingestion by Table | Column chart (stacked) | GB per day for the top 10 tables, with the rest grouped as Other |
| 🔝 Top Tables | Grid | GB, share of total, change from the previous period and estimated cost per table |
| 🚨 Ingestion Anomalies | Grid | Tables with an unusual spike or drop in the last 3 days |
| 🖥️ Top Noisy Sources | Grid | The hosts, firewalls and devices sending the most billable data |
| ⏱️ Last Seen per Table | Grid | Minutes since each key table last received data, against a per-table threshold |
| 🔌 Connector Health | Grid | Latest status, failures and last success for each data connector |
| 📉 Silent Sources | Grid | Hosts and appliances that sent data last week but nothing in the last 24 hours |
| 🐢 Ingestion Latency | Grid | Average, p95 and max delay between event time and ingestion per table |
| 🫀 Agent Heartbeat | Grid | Azure Monitor Agent machines that stopped sending heartbeats |
| ⚠️ Rule & Automation Failures | Grid | Analytics and automation rules that failed or warned |

**Notes**
- **Connector Health** and **Rule & Automation Failures** read `SentinelHealth`. Turn it on in **Sentinel > Settings > Settings > Auditing and health monitoring**. Not every connector reports health; Defender XDR, Threat Intelligence, AWS S3 and codeless (CCF) connectors do.
- Cost is an estimate. Set `PricePerGB` to your effective rate (pay-as-you-go or commitment tier, Sentinel plus Log Analytics).
- **Last Seen per Table** only checks the tables in its list. Add the tables your detections depend on and set a threshold for each.
- Panels that scan raw tables (Top Noisy Sources, Silent Sources, Latency) use short fixed lookbacks to keep them fast.

---

## 📊 Ingestion Summary
Tiles. Title: `Metric`, Left: `Value`.

```kql
let PricePerGB = 5.2;   // your effective $/GB (Sentinel + Log Analytics, after commitment discounts)
let U = Usage | where TimeGenerated > ago(30d);
let Today = toscalar(U | where TimeGenerated > startofday(now()) and IsBillable == true | summarize sum(Quantity) / 1024.0);
let Avg7 = toscalar(U | where TimeGenerated > ago(7d) and IsBillable == true | summarize sum(Quantity) / 1024.0 / 7);
let Month = toscalar(U | where IsBillable == true | summarize sum(Quantity) / 1024.0);
let Free = toscalar(U | where IsBillable == false | summarize sum(Quantity) / 1024.0);
let Tables = toscalar(U | where TimeGenerated > ago(1d) and Quantity > 0 | summarize dcount(DataType));
print Rows = pack_array(
    bag_pack("Metric", "📥 Today", "Value", strcat(round(Today, 2), " GB")),
    bag_pack("Metric", "📅 7-Day Daily Avg", "Value", strcat(round(Avg7, 2), " GB")),
    bag_pack("Metric", "🗓️ Last 30 Days", "Value", strcat(round(Month, 1), " GB")),
    bag_pack("Metric", "💰 Est. Monthly Cost", "Value", strcat("$", round(Avg7 * 30 * PricePerGB, 0))),
    bag_pack("Metric", "🆓 Free Data (30d)", "Value", strcat(round(Free, 1), " GB")),
    bag_pack("Metric", "🗂️ Active Tables", "Value", tostring(Tables)))
| mv-expand Row = Rows
| project Metric = tostring(Row.Metric), Value = tostring(Row.Value)
```

## 📈 Daily Ingestion by Table
Column chart, stacked. Billable data only.

```kql
let Top = Usage
    | where TimeGenerated {TimeRange}
    | where IsBillable == true
    | summarize GB = sum(Quantity) by DataType
    | top 10 by GB
    | project DataType;
Usage
| where TimeGenerated {TimeRange}
| where IsBillable == true
| extend Table = iff(DataType in (Top), DataType, "Other")
| summarize GB = round(sum(Quantity) / 1024.0, 3) by bin(TimeGenerated, 1d), Table
| render columnchart
```

## 🔝 Top Tables
Grid. Compares the selected range with the same-length period before it.

```kql
let PricePerGB = 5.2;
let Start = {TimeRange:start};
let End = {TimeRange:end};
let Span = End - Start;
let Cur = Usage
    | where TimeGenerated between (Start .. End)
    | where IsBillable == true
    | summarize GB = sum(Quantity) / 1024.0 by DataType, Solution;
let Prev = Usage
    | where TimeGenerated between ((Start - Span) .. Start)
    | where IsBillable == true
    | summarize PrevGB = sum(Quantity) / 1024.0 by DataType;
let Total = toscalar(Cur | summarize sum(GB));
Cur
| lookup kind=leftouter Prev on DataType
| extend PctOfTotal = round(100.0 * GB / Total, 1),
         Change = case(isnull(PrevGB) or PrevGB == 0, "🆕 New",
                       GB > PrevGB * 1.5, strcat("📈 +", round(100.0 * (GB - PrevGB) / PrevGB, 0), "%"),
                       GB < PrevGB * 0.5, strcat("📉 ", round(100.0 * (GB - PrevGB) / PrevGB, 0), "%"),
                       strcat(round(100.0 * (GB - PrevGB) / PrevGB, 0), "%")),
         EstCost = round(GB * PricePerGB, 2)
| sort by GB desc
| project Table = DataType, Solution, GB = round(GB, 3), PctOfTotal, PrevGB = round(PrevGB, 3), Change, EstCost
```

## 🚨 Ingestion Anomalies
Grid. Daily volume per table over 30 days, flagged where the last 3 days fall outside the expected range. A drop is often a broken connector; a spike is often a misconfigured source or noisy new logging.

```kql
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| make-series MB = sum(Quantity) default = 0 on TimeGenerated from startofday(ago(30d)) to startofday(now()) step 1d by DataType
| extend (Flags, Score, Baseline) = series_decompose_anomalies(MB, 2.5, -1, "linefit")
| mv-expand TimeGenerated to typeof(datetime), MB to typeof(double), Flags to typeof(int), Baseline to typeof(double)
| where TimeGenerated >= startofday(ago(3d)) and Flags != 0
| project Day = TimeGenerated,
          Table = DataType,
          Direction = iff(Flags > 0, "📈 Spike", "📉 Drop"),
          GB = round(MB / 1024.0, 3),
          ExpectedGB = round(Baseline / 1024.0, 3)
| sort by Day desc, Table asc
```

## 🖥️ Top Noisy Sources
Grid. Last 24 hours. Shows which machines or appliances drive volume in each table.

```kql
union withsource = Table isfuzzy = true
    SecurityEvent, Syslog, CommonSecurityLog, Event, W3CIISLog,
    DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents, DeviceRegistryEvents, DeviceImageLoadEvents
| where TimeGenerated > ago(1d)
| where _IsBillable == true
| extend Source = tolower(coalesce(column_ifexists("DeviceName", ""), column_ifexists("Computer", ""), column_ifexists("DeviceVendor", "")))
| summarize MB = round(sum(_BilledSize) / 1024.0 / 1024.0, 2), Events = count() by Table, Source
| top 25 by MB desc
```

## ⏱️ Last Seen per Table
Grid. Edit the list to match the tables your detections depend on. `MaxMinutes` is how long a table can be quiet before it's flagged.

```kql
let Expected = datatable(Table:string, MaxMinutes:long) [
    "SigninLogs", 60, "AADNonInteractiveUserSignInLogs", 60, "AuditLogs", 120, "OfficeActivity", 120,
    "SecurityEvent", 60, "DeviceProcessEvents", 30, "DeviceNetworkEvents", 30, "DeviceEvents", 60,
    "EmailEvents", 120, "CommonSecurityLog", 30, "Syslog", 60, "AzureActivity", 240, "SecurityAlert", 1440, "Heartbeat", 15];
let Seen = union withsource = Table isfuzzy = true
        SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, OfficeActivity, SecurityEvent,
        DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents, EmailEvents, CommonSecurityLog, Syslog,
        AzureActivity, SecurityAlert, Heartbeat
    | where TimeGenerated > ago(2d)
    | summarize LastEvent = max(TimeGenerated), LastIngested = max(ingestion_time()) by Table;
Expected
| join kind=leftouter Seen on Table
| extend MinutesSince = iff(isnull(LastIngested), long(null), datetime_diff("minute", now(), LastIngested))
| extend Status = case(isnull(LastIngested), "⚫ No data (2d)",
                       MinutesSince > MaxMinutes * 4, "🔴 Stopped",
                       MinutesSince > MaxMinutes, "🟡 Late",
                       "🟢 OK")
| extend SevRank = case(Status startswith "⚫", 1, Status startswith "🔴", 2, Status startswith "🟡", 3, 4)
| sort by SevRank asc, MinutesSince desc
| project Table, Status, MinutesSince, MaxMinutes, LastIngested, LastEvent
```

## 🔌 Connector Health
Grid. Needs `SentinelHealth` turned on.

```kql
SentinelHealth
| where TimeGenerated {TimeRange}
| where SentinelResourceType == "Data connector"
| summarize arg_max(TimeGenerated, Status, Reason, Description),
            Failures = countif(Status == "Failure"),
            LastSuccess = maxif(TimeGenerated, Status == "Success")
         by SentinelResourceName, SentinelResourceKind
| extend Health = case(Status == "Success", "🟢 Healthy", Status == "Failure", "🔴 Failing", strcat("🟡 ", Status))
| extend SevRank = case(Health startswith "🔴", 1, Health startswith "🟡", 2, 3)
| sort by SevRank asc, Failures desc
| project Connector = SentinelResourceName, Kind = SentinelResourceKind, Health, Failures, LastSuccess,
          LastEvent = TimeGenerated, Reason, Description
```

## 📉 Silent Sources
Grid. Sources that sent data in the 7 days before yesterday but nothing in the last 24 hours. Common causes: a decommissioned server, a stopped agent or a firewall that lost its Syslog target.

```kql
union withsource = Table isfuzzy = true SecurityEvent, Syslog, CommonSecurityLog, Event, W3CIISLog
| where TimeGenerated > ago(8d)
| extend Source = tolower(coalesce(column_ifexists("DeviceName", ""), column_ifexists("Computer", "")))
| where isnotempty(Source)
| summarize LastSeen = max(TimeGenerated), EventsPriorWeek = countif(TimeGenerated < ago(1d)) by Table, Source
| where LastSeen < ago(1d) and EventsPriorWeek > 0
| extend HoursSilent = datetime_diff("hour", now(), LastSeen)
| sort by HoursSilent desc
| project Table, Source, HoursSilent, LastSeen, EventsPriorWeek
```

## 🐢 Ingestion Latency
Grid. Last 6 hours. Late data delays every scheduled rule that reads it: a rule that runs every 5 minutes can miss events that arrive 20 minutes late.

```kql
union withsource = Table isfuzzy = true
    SigninLogs, AuditLogs, OfficeActivity, SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents,
    EmailEvents, CommonSecurityLog, Syslog, SecurityAlert
| where TimeGenerated > ago(6h)
| extend LatencyMin = datetime_diff("second", ingestion_time(), TimeGenerated) / 60.0
| summarize AvgMin = round(avg(LatencyMin), 1),
            P95Min = round(percentile(LatencyMin, 95), 1),
            MaxMin = round(max(LatencyMin), 1),
            Events = count()
         by Table
| extend Status = case(P95Min > 30, "🔴 Slow", P95Min > 10, "🟡 Lagging", "🟢 OK")
| sort by P95Min desc
| project Table, Status, AvgMin, P95Min, MaxMin, Events
```

## 🫀 Agent Heartbeat
Grid. Azure Monitor Agent machines, worst first.

```kql
Heartbeat
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, Category, Version, OSType, OSName, ComputerIP, ResourceGroup) by Computer
| extend MinutesSince = datetime_diff("minute", now(), TimeGenerated)
| extend Status = case(MinutesSince > 1440, "🔴 Offline > 1 day", MinutesSince > 15, "🟡 Missed heartbeats", "🟢 Healthy")
| sort by MinutesSince desc
| project Computer, Status, MinutesSince, LastHeartbeat = TimeGenerated, Agent = Category, Version, OSType, OSName, ComputerIP, ResourceGroup
```

## ⚠️ Rule & Automation Failures
Grid. Needs `SentinelHealth` turned on. Only rules with at least one failure or warning in the range.

```kql
SentinelHealth
| where TimeGenerated {TimeRange}
| where SentinelResourceType in ("Analytics Rule", "Automation rule")
| summarize arg_max(TimeGenerated, Status, Reason, Description),
            Runs = count(),
            Issues = countif(Status != "Success"),
            LastIssue = maxif(TimeGenerated, Status != "Success"),
            Reasons = make_set_if(Reason, Status != "Success", 3)
         by SentinelResourceName, SentinelResourceType, SentinelResourceKind
| where Issues > 0
| extend Health = case(Status == "Success", "🟡 Recovered", Status == "Failure", "🔴 Failing", strcat("🟡 ", Status))
| sort by Issues desc
| project Rule = SentinelResourceName, Type = SentinelResourceType, Kind = SentinelResourceKind, Health, Issues, Runs,
          LastIssue, Reasons, LatestStatus = Status, Description
```
