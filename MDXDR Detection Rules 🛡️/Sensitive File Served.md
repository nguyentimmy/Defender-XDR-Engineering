# 🔓 Sensitive File Served

A web server returned a sensitive file with a 2xx response. Treat every alert as a possible secret exposure.

> 📌 Part of the **AI & Autonomous Threats** detection set. Built from workbook panel 17 (Sensitive Path Probes). This is a Microsoft Sentinel scheduled analytic rule.

| | |
|---|---|
| 🗂️ Data sources | IIS logs (`W3CIISLog`) through Azure Monitor Agent |
| 🔴 Default severity | High |
| ⏱️ Schedule | Every 1 hour, looking back 2 hours |

---

## 🔎 Query

```kql
let Allowlist = dynamic([]);   // internal scanners that are expected to hit these paths
let SensitivePaths = @"(?i)(/\.env|/\.git(/|$)|/\.aws/|/\.ssh/|/\.htpasswd|/\.npmrc|/\.dockercfg|/\.docker/|/\.kube/|wp-config\.php|/web\.config|/appsettings(\.\w+)?\.json|id_rsa|\.(sql|bak)$)";
W3CIISLog
| where TimeGenerated > ago(2h)
| where ingestion_time() > ago(1h)
| where cIP !in (Allowlist)
| where csUriStem matches regex SensitivePaths
| where tostring(scStatus) startswith "2"
| summarize Hits = count(),
            Paths = make_set(csUriStem, 20),
            MaxBytes = max(scBytes),
            UserAgents = make_set(csUserAgent, 5),
            Site = take_any(csHost),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by SourceIP = cIP, WebServer = Computer
| extend FirstPath = tostring(Paths[0])
```

## ⚙️ Rule Settings

| Setting | Value |
|---------|-------|
| 📛 Name | AI - Sensitive File Served |
| 🔴 Severity | High |
| ⏱️ Run every / Lookup data from | 1 hour / 2 hours |
| 🎯 Alert threshold | Number of results > 0 |
| 🧾 Event grouping | Trigger an alert for each event |
| 🧩 Entities | IP: `Address` = `SourceIP` · Host: `HostName` = `WebServer` · URL: `Url` = `FirstPath` |
| 📋 Custom details | `Paths`, `Hits`, `MaxBytes`, `UserAgents`, `Site` |
| 🏷️ Alert name format | `Sensitive file served by {{WebServer}}: {{FirstPath}}` |
| 🗂️ Alert grouping | Group into one incident when **Host** matches, within 24 hours |

## 🛠️ Tuning

- The path list is narrower than panel 17 on purpose. It leaves out paths that are often legitimate (`/backup` routes, `/actuator/health`, generic `config.json`).
- If an app serves one of these paths on purpose, fix it rather than excluding it. Configs and keys shouldn't be in a web root.

## 📋 Response

Confirm the file contents, rotate every credential in it, remove the file from the web root, and check Recon to Sign-In for the same source IP.

---

## 🧭 Avoiding Duplicate Alerts

The rule runs every hour but looks back further, so it can catch IIS logs that arrive late. To stop the same activity alerting every hour, the query only returns results when new data arrived in the last hour (`ingestion_time() > ago(1h)`). This also catches events that were ingested late, which a plain `TimeGenerated` filter would miss.

---

## 🛠️ Creating the Rule in Sentinel

1. Go to **Microsoft Sentinel > Analytics > Create > Scheduled query rule**. In the Defender portal: **Microsoft Sentinel > Configuration > Analytics**.
2. **General:** enter the name and severity from Rule Settings.
3. **Set rule logic:** paste the query. Map entities, add custom details, and set the alert name format under **Alert details**. Set the schedule and threshold.
4. **Incident settings:** keep incident creation on and set alert grouping from the table.
5. **Automated response:** attach automation rules if you want (for example a notification or enrichment playbook).
6. **Review + create.**

---

## 🧪 Lab Testing

Create `C:\inetpub\wwwroot\appsettings.json` with dummy content and request it. IIS doesn't serve unknown extensions like `.env` by default, which is one reason to test with `.json`.

Events take up to about 15 minutes to arrive. Run the query in **Logs** first, then wait for the next scheduled run.
