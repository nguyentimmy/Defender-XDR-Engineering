# 📊 KPI Metrics Overview

The KPI Metrics tab of the Security Operations Workbook: SOC optimization. It looks back at closed and open incidents in `SecurityIncident` to measure how fast the SOC detects, picks up and resolves incidents, how the work is spread across analysts, and how much of the alerting is real.

> **Disclaimer:** This workbook does not replace alert triage. Alerts and incidents should still be investigated for a deeper investigation.

| Panel | Visualization | Shows |
|---|---|---|
| 📊 KPI Summary | Tiles | MTTD, MTTA, MTTR, incidents closed, and true, benign and false positive rates |
| ⏱️ Response Times by Severity | Grid | Average and median MTTD, MTTA and MTTR per severity |
| 📈 MTTA & MTTR Trend | Line chart | Weekly average time to acknowledge and resolve |
| 📉 Created vs. Closed | Line chart | Incidents opened and closed per day, so a growing backlog shows up early |
| 👥 Analyst Workload | Grid | Per analyst: assigned, open, closed, average MTTA and MTTR, true positive rate |
| 📂 Incidents by Analyst and Status | Bar chart (stacked) | New, Active and Closed per analyst |
| 🏷️ Classification Rates | Pie chart | True positive, benign positive, false positive and undetermined |
| 🔧 Tuning Candidates | Grid | Detections with the highest share of benign and false positive closures |

**Notes**
- **MTTD** is the time from the first activity in the incident to when the incident was created. **MTTA** is the time to the first update that sets an owner or moves it out of **New**. **MTTR** is the time from creation to close.
- Each incident is counted once at its latest state. Times are in hours.
- Medians are shown next to averages because one long-running incident can skew an average.

---

## 📊 KPI Summary
Tiles. Title: `Metric`, Left: `Value`.

```kql
let Inc = SecurityIncident
    | where TimeGenerated {TimeRange}
    | where CreatedTime {TimeRange}
    | summarize arg_max(TimeGenerated, *),
                FirstAck = minif(TimeGenerated, Status != "New" or isnotempty(tostring(Owner.assignedTo)))
             by IncidentNumber
    | extend MTTD = datetime_diff("minute", CreatedTime, FirstActivityTime) / 60.0,
             MTTA = datetime_diff("minute", FirstAck, CreatedTime) / 60.0,
             MTTR = iff(Status == "Closed", datetime_diff("minute", ClosedTime, CreatedTime) / 60.0, real(null));
Inc
| summarize MTTD = avgif(MTTD, MTTD >= 0),
            MTTA = avgif(MTTA, MTTA >= 0),
            MTTR = avgif(MTTR, MTTR >= 0),
            Closed = countif(Status == "Closed"),
            Classified = countif(isnotempty(Classification)),
            TP = countif(Classification == "TruePositive"),
            BP = countif(Classification == "BenignPositive"),
            FP = countif(Classification == "FalsePositive")
| extend Rows = pack_array(
    bag_pack("Metric", "🔎 MTTD", "Value", iff(isnan(MTTD) or isnull(MTTD), "-", strcat(round(MTTD, 1), " h"))),
    bag_pack("Metric", "⏱️ MTTA", "Value", iff(isnan(MTTA) or isnull(MTTA), "-", strcat(round(MTTA, 1), " h"))),
    bag_pack("Metric", "🏁 MTTR", "Value", iff(isnan(MTTR) or isnull(MTTR), "-", strcat(round(MTTR, 1), " h"))),
    bag_pack("Metric", "✅ Closed", "Value", tostring(Closed)),
    bag_pack("Metric", "🎯 True Positive", "Value", iff(Classified == 0, "-", strcat(round(100.0 * TP / Classified, 0), "%"))),
    bag_pack("Metric", "🟢 Benign Positive", "Value", iff(Classified == 0, "-", strcat(round(100.0 * BP / Classified, 0), "%"))),
    bag_pack("Metric", "⚪ False Positive", "Value", iff(Classified == 0, "-", strcat(round(100.0 * FP / Classified, 0), "%"))))
| mv-expand Row = Rows
| project Metric = tostring(Row.Metric), Value = tostring(Row.Value)
```

## ⏱️ Response Times by Severity
Grid.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *),
            FirstAck = minif(TimeGenerated, Status != "New" or isnotempty(tostring(Owner.assignedTo)))
         by IncidentNumber
| extend MTTD = datetime_diff("minute", CreatedTime, FirstActivityTime) / 60.0,
         MTTA = datetime_diff("minute", FirstAck, CreatedTime) / 60.0,
         MTTR = iff(Status == "Closed", datetime_diff("minute", ClosedTime, CreatedTime) / 60.0, real(null))
| summarize Incidents = count(),
            AvgMTTD = round(avgif(MTTD, MTTD >= 0), 1), MedMTTD = round(percentileif(MTTD, 50, MTTD >= 0), 1),
            AvgMTTA = round(avgif(MTTA, MTTA >= 0), 1), MedMTTA = round(percentileif(MTTA, 50, MTTA >= 0), 1),
            AvgMTTR = round(avgif(MTTR, MTTR >= 0), 1), MedMTTR = round(percentileif(MTTR, 50, MTTR >= 0), 1)
         by Severity
| extend SevOrder = case(Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4)
| sort by SevOrder asc
| project Severity = case(Severity == "High", "🔴 High", Severity == "Medium", "🟠 Medium", Severity == "Low", "🟡 Low", "⚪ Informational"),
          Incidents, AvgMTTD, MedMTTD, AvgMTTA, MedMTTA, AvgMTTR, MedMTTR
```

## 📈 MTTA & MTTR Trend
Line chart. Weekly, by the week the incident was created.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *),
            FirstAck = minif(TimeGenerated, Status != "New" or isnotempty(tostring(Owner.assignedTo)))
         by IncidentNumber
| extend MTTA = datetime_diff("minute", FirstAck, CreatedTime) / 60.0,
         MTTR = iff(Status == "Closed", datetime_diff("minute", ClosedTime, CreatedTime) / 60.0, real(null))
| summarize ['MTTA (h)'] = round(avgif(MTTA, MTTA >= 0), 1), ['MTTR (h)'] = round(avgif(MTTR, MTTR >= 0), 1)
         by Week = startofweek(CreatedTime)
| sort by Week asc
| render linechart
```

## 📉 Created vs. Closed
Line chart. If Created stays above Closed, the backlog is growing.

```kql
let Inc = SecurityIncident
    | where TimeGenerated {TimeRange}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber;
union
    (Inc | where CreatedTime {TimeRange} | summarize Incidents = count() by Day = bin(CreatedTime, 1d) | extend Series = "Created"),
    (Inc | where Status == "Closed" and ClosedTime {TimeRange} | summarize Incidents = count() by Day = bin(ClosedTime, 1d) | extend Series = "Closed")
| sort by Day asc
| render linechart
```

## 👥 Analyst Workload
Grid.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *),
            FirstAck = minif(TimeGenerated, Status != "New" or isnotempty(tostring(Owner.assignedTo)))
         by IncidentNumber
| extend Analyst = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), "Unassigned"),
         MTTA = datetime_diff("minute", FirstAck, CreatedTime) / 60.0,
         MTTR = iff(Status == "Closed", datetime_diff("minute", ClosedTime, CreatedTime) / 60.0, real(null))
| summarize Assigned = count(),
            Open = countif(Status != "Closed"),
            Closed = countif(Status == "Closed"),
            HighSeverity = countif(Severity == "High"),
            AvgMTTA = round(avgif(MTTA, MTTA >= 0), 1),
            AvgMTTR = round(avgif(MTTR, MTTR >= 0), 1),
            TP = countif(Classification == "TruePositive"),
            Classified = countif(isnotempty(Classification))
         by Analyst
| extend TruePositiveRate = iff(Classified == 0, "-", strcat(round(100.0 * TP / Classified, 0), "%"))
| sort by Open desc, Assigned desc
| project Analyst, Assigned, Open, Closed, HighSeverity, AvgMTTA, AvgMTTR, TruePositiveRate
```

## 📂 Incidents by Analyst and Status
Bar chart, stacked by status.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend Analyst = coalesce(tostring(Owner.assignedTo), tostring(Owner.email), "Unassigned")
| summarize Incidents = count() by Analyst, Status
| render barchart kind=stacked
```

## 🏷️ Classification Rates
Pie chart. Closed incidents only.

```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend Classification = case(Classification == "TruePositive", "🎯 True Positive",
                               Classification == "BenignPositive", "🟢 Benign Positive",
                               Classification == "FalsePositive", "⚪ False Positive",
                               "❔ Undetermined")
| summarize Incidents = count() by Classification
| sort by Incidents desc
```

## 🔧 Tuning Candidates
Grid. Detections closed at least 5 times, ranked by how often they turn out benign or false. A high noise rate is a tuning task: feed it back into the analytics rule or its exclusions.

```kql
let MinClosed = 5;
SecurityIncident
| where TimeGenerated {TimeRange}
| where CreatedTime {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| summarize Closed = count(),
            TruePositive = countif(Classification == "TruePositive"),
            BenignPositive = countif(Classification == "BenignPositive"),
            FalsePositive = countif(Classification == "FalsePositive"),
            TopReason = take_anyif(ClassificationReason, Classification in ("BenignPositive", "FalsePositive")),
            AvgHoursToClose = round(avg(datetime_diff("minute", ClosedTime, CreatedTime) / 60.0), 1)
         by Title
| where Closed >= MinClosed
| extend NoiseRate = round(100.0 * (BenignPositive + FalsePositive) / Closed, 0)
| sort by NoiseRate desc, Closed desc
| take 15
| project Title, Closed, NoiseRate, TruePositive, BenignPositive, FalsePositive, TopReason, AvgHoursToClose
```
