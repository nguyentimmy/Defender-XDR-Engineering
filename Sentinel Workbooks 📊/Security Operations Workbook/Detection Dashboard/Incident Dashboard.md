# 🗂️ Incident Dashboard

The **Incident Dashboard** group of the Detection Dashboard tab, below the [Alert Dashboard](Alert%20Dashboard.md) group. Where Alert Dashboard counts alerts, this view counts incidents (cases): what's open, who owns it, how old it is, how it was closed and what keeps coming back. It's built on the Sentinel `SecurityIncident` table, which also holds Defender XDR incidents synced through the connector.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

**Parameters:** `Owner` (dropdown of incident owners plus Unassigned; default All), `TimeRange`.

| Panel | Visualization | Shows |
|---|---|---|
| 📊 Incident Summary | Tiles | Total, open, unassigned, open High, SLA breached, closed, MTTA, MTTR and true positive rate |
| 📋 Open Incident Queue | Grid | Every open incident with severity, owner, age, last update, alerts, products, tactics and SLA flag |
| 🥧 Incidents by Severity | Pie chart | Incident count by severity |
| 📂 Incidents by Status | Pie chart | New vs. Active vs. Closed |
| 🏷️ Closed by Classification | Bar chart | True positive, benign positive, false positive and undetermined, with the reason |
| 🔁 Top 10 Recurring Incidents | Grid | Incident titles that keep coming back, with how they're usually closed |
| 🎯 Most Involved Entities | Grid | Hosts, accounts and IPs that show up across the most incidents |
| 📈 Incidents Over Time by Severity | Time chart | Incident volume trend by severity |

**Notes**
- Each incident is counted once at its latest state (`arg_max` by `IncidentNumber`). `SecurityIncident` writes a new row on every update.
- **MTTA** is the time from creation to the first update that sets an owner or moves the incident out of **New**. **MTTR** is the time from creation to close.
- SLA targets are set at the top of the queue and summary queries: High 4 hours, Medium 24 hours, Low 72 hours. Change them to match your SOC.

---

## 📊 Incident Summary
Tiles. Title: `Metric`, Left: `Value`.

```kql
let SlaHours = dynamic({"High": 4, "Medium": 24, "Low": 72, "Informational": 168});
let Inc = SecurityIncident
    | where TimeGenerated {TimeRange}
    | where CreatedTime {TimeRange}
    | summarize arg_max(TimeGenerated, *),
                FirstAck = minif(TimeGenerated, Status != "New" or isnotempty(tostring(Owner.assignedTo)))
             by IncidentNumber
    | extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
    | where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
    | extend IsOpen = Status != "Closed",
             AgeHours = datetime_diff("minute", iff(Status == "Closed", ClosedTime, now()), CreatedTime) / 60.0,
             AckHours = datetime_diff("minute", FirstAck, CreatedTime) / 60.0;
Inc
| summarize Total = count(),
            Open = countif(IsOpen),
            Unassigned = countif(IsOpen and isempty(OwnerName)),
            OpenHigh = countif(IsOpen and Severity == "High"),
            Breached = countif(IsOpen and AgeHours > todouble(SlaHours[Severity])),
            Closed = countif(not(IsOpen)),
            MTTA = avgif(AckHours, AckHours >= 0),
            MTTR = avgif(AgeHours, not(IsOpen)),
            TP = countif(Classification == "TruePositive"),
            Classified = countif(isnotempty(Classification))
| extend Rows = pack_array(
    bag_pack("Metric", "🗂️ Total", "Value", tostring(Total)),
    bag_pack("Metric", "📂 Open", "Value", tostring(Open)),
    bag_pack("Metric", "🙋 Unassigned", "Value", tostring(Unassigned)),
    bag_pack("Metric", "🔴 Open High", "Value", tostring(OpenHigh)),
    bag_pack("Metric", "⏰ SLA Breached", "Value", tostring(Breached)),
    bag_pack("Metric", "✅ Closed", "Value", tostring(Closed)),
    bag_pack("Metric", "⏱️ MTTA", "Value", iff(isnan(MTTA) or isnull(MTTA), "-", strcat(round(MTTA, 1), " h"))),
    bag_pack("Metric", "🏁 MTTR", "Value", iff(isnan(MTTR) or isnull(MTTR), "-", strcat(round(MTTR, 1), " h"))),
    bag_pack("Metric", "🎯 True Positive Rate", "Value", iff(Classified == 0, "-", strcat(round(100.0 * TP / Classified, 0), "%"))))
| mv-expand Row = Rows
| project Metric = tostring(Row.Metric), Value = tostring(Row.Value)
```

## 📋 Open Incident Queue
Grid. Sorted by SLA breach, then severity, then oldest first.

```kql
let SlaHours = dynamic({"High": 4, "Medium": 24, "Low": 72, "Informational": 168});
let StaleHours = 24;
SecurityIncident
| where TimeGenerated {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status != "Closed"
| extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
| where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
| extend AgeHours = round(datetime_diff("minute", now(), CreatedTime) / 60.0, 1),
         SinceUpdateHours = round(datetime_diff("minute", now(), LastModifiedTime) / 60.0, 1),
         Sla = todouble(SlaHours[Severity])
| extend Flags = strcat_array(array_concat(
    iff(AgeHours > Sla, dynamic(["⏰ SLA Breached"]), dynamic([])),
    iff(isempty(OwnerName), dynamic(["🙋 Unassigned"]), dynamic([])),
    iff(SinceUpdateHours > StaleHours, dynamic(["💤 Stale"]), dynamic([]))), " ")
| extend SevOrder = case(Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4)
| extend Breach = iff(AgeHours > Sla, 0, 1)
| sort by Breach asc, SevOrder asc, AgeHours desc
| project
    Incident = IncidentNumber,
    Title,
    Severity = case(Severity == "High", "🔴 High", Severity == "Medium", "🟠 Medium", Severity == "Low", "🟡 Low", "⚪ Informational"),
    Status,
    Owner = iff(isempty(OwnerName), "Unassigned", OwnerName),
    Flags,
    AgeHours,
    SinceUpdateHours,
    Alerts = toint(AdditionalData.alertsCount),
    Products = strcat_array(todynamic(AdditionalData.alertProductNames), ", "),
    Tactics = strcat_array(todynamic(AdditionalData.tactics), ", "),
    CreatedTime,
    IncidentUrl
```

## 🥧 Incidents by Severity
Pie chart. Series colors: High red, Medium orange, Low yellow, Informational gray.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
| where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
| extend Severity = case(Severity == "High", "🔴 High", Severity == "Medium", "🟠 Medium", Severity == "Low", "🟡 Low", "⚪ Informational")
| summarize Incidents = count() by Severity
| sort by Incidents desc
```

## 📂 Incidents by Status
Pie chart. Colors: New red, Active yellow, Closed green.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
| where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
| summarize Incidents = count() by Status
```

## 🏷️ Closed by Classification
Bar chart. Stacked by reason.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
| where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
| extend Classification = case(Classification == "TruePositive", "🎯 True Positive",
                               Classification == "BenignPositive", "🟢 Benign Positive",
                               Classification == "FalsePositive", "⚪ False Positive",
                               "❔ Undetermined"),
         Reason = iff(isempty(ClassificationReason), "Not set", ClassificationReason)
| summarize Incidents = count() by Classification, Reason
| sort by Incidents desc
```

## 🔁 Top 10 Recurring Incidents
Grid. The incidents that keep coming back. A title with a high false or benign positive share is a tuning candidate.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
| where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
| extend SevRank = case(Severity == "High", 4, Severity == "Medium", 3, Severity == "Low", 2, 1)
| summarize Incidents = count(),
            Open = countif(Status != "Closed"),
            TruePositive = countif(Classification == "TruePositive"),
            BenignOrFalse = countif(Classification in ("BenignPositive", "FalsePositive")),
            SevRank = max(SevRank),
            Products = take_any(strcat_array(todynamic(AdditionalData.alertProductNames), ", ")),
            AvgHoursToClose = round(avgif(datetime_diff("minute", ClosedTime, CreatedTime) / 60.0, Status == "Closed"), 1),
            FirstSeen = min(CreatedTime),
            LastSeen = max(CreatedTime)
         by Title
| top 10 by Incidents desc
| extend NoiseRate = iff(TruePositive + BenignOrFalse == 0, "-", strcat(round(100.0 * BenignOrFalse / (TruePositive + BenignOrFalse), 0), "%")),
         Severity = case(SevRank == 4, "🔴 High", SevRank == 3, "🟠 Medium", SevRank == 2, "🟡 Low", "⚪ Informational")
| project Title, Incidents, Open, Severity, TruePositive, BenignOrFalse, NoiseRate, AvgHoursToClose, Products, FirstSeen, LastSeen
```

## 🎯 Most Involved Entities
Grid. Hosts, accounts and IPs that appear in the most incidents. An entity in several open incidents is worth one investigation instead of many.

```kql
let Inc = SecurityIncident
    | where TimeGenerated {TimeRange}
    | where CreatedTime {TimeRange}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
    | where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
    | mv-expand AlertId = AlertIds to typeof(string)
    | project IncidentNumber, Status, Severity, AlertId;
let Alerts = SecurityAlert
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, Entities) by SystemAlertId;
Inc
| join kind=inner Alerts on $left.AlertId == $right.SystemAlertId
| mv-apply E = parse_json(Entities) on (
    extend T = tolower(tostring(E.Type))
    | extend Entity = case(
        T == "host", tolower(coalesce(tostring(E.HostName), tostring(E.FQDN))),
        T == "account", tolower(iff(isnotempty(tostring(E.UPNSuffix)), strcat(tostring(E.Name), "@", tostring(E.UPNSuffix)), tostring(E.Name))),
        T == "ip", tostring(E.Address),
        "")
    | where isnotempty(Entity)
    | project Type = case(T == "host", "🖥️ Host", T == "account", "👤 Account", "🌐 IP"), Entity)
| summarize Incidents = dcount(IncidentNumber),
            OpenIncidents = dcountif(IncidentNumber, Status != "Closed"),
            HighIncidents = dcountif(IncidentNumber, Severity == "High"),
            IncidentNumbers = make_set(IncidentNumber, 10)
         by Type, Entity
| top 15 by Incidents desc
```

## 📈 Incidents Over Time by Severity
Time chart. Same severity colors as the pie. Change `1d` to `1h` for ranges under about 3 days.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend OwnerName = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), tostring(Owner.userPrincipalName))
| where "{Owner}" == "*" or iff(isempty(OwnerName), "Unassigned", OwnerName) == "{Owner}"
| summarize Incidents = count() by bin(CreatedTime, 1d), Severity
| render timechart
```
