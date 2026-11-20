# 🤖 LLM-Driven Offensive Agent

The main signature of an autonomous attack tool like ARTEX running on one of your hosts: a non-browser process calls an LLM API, and the same host runs offensive tooling.

> 📌 Part of the **AI & Autonomous Threats** detection set. Built from workbook panel 6 (LLM-Driven Offensive Agent). This is a Microsoft Sentinel scheduled analytic rule.

| | |
|---|---|
| 🗂️ Data sources | Microsoft Defender for Endpoint (`DeviceNetworkEvents`, `DeviceProcessEvents`) through the Defender XDR connector |
| 🔴 Default severity | High (overridden per alert by the `Severity` column) |
| ⏱️ Schedule | Every 1 hour, looking back 3 hours |

---

## 🔎 Query

```kql
let Window = 3h;
let LLMDomains = dynamic([
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.mistral.ai", "api.groq.com", "openrouter.ai", "api.together.xyz",
    "api.deepseek.com", "api.x.ai", "api.cohere.com", "api.cohere.ai",
    "api.perplexity.ai", "bedrock-runtime"]);
let SanctionedProcs = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "msedgewebview2.exe",
    "claude.exe", "chatgpt.exe", "code.exe", "ms-teams.exe", "teams.exe"]);
let Tools = dynamic([
    "httpx", "subfinder", "katana", "ffuf", "nuclei", "naabu", "amass",
    "gobuster", "dnsx", "httprobe", "nmap", "masscan", "sqlmap"]);
let ExcludedDevices = dynamic([]);   // approved pentest / red team hosts
let LLMHosts = DeviceNetworkEvents
    | where TimeGenerated > ago(Window)
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
    | where InitiatingProcessFileName !in~ (SanctionedProcs)
    | summarize LLMCalls = count(),
                LLMProcesses = make_set(InitiatingProcessFileName, 10),
                LLMDestinations = make_set(coalesce(RemoteUrl, RemoteIP), 10),
                LLMFirstSeen = min(TimeGenerated),
                LLMLastSeen = max(TimeGenerated)
             by DeviceId, DeviceName;
let ToolHosts = DeviceProcessEvents
    | where TimeGenerated > ago(Window)
    | where FileName in~ (Tools)
        or (FileName startswith "python" and ProcessCommandLine has "sqlmap")
    | summarize ToolRuns = count(),
                ToolsSeen = make_set(FileName, 20),
                SampleCmds = make_set(ProcessCommandLine, 5),
                Account = take_any(AccountName),
                ToolLastSeen = max(TimeGenerated)
             by DeviceId;
LLMHosts
| where DeviceName !in~ (ExcludedDevices)
| join kind=inner ToolHosts on DeviceId
| where max_of(LLMLastSeen, ToolLastSeen) > ago(1h)
| extend DistinctTools = array_length(ToolsSeen)
| extend Severity = iff(DistinctTools >= 3, "High", "Medium")
| project LLMFirstSeen, Severity, DeviceName, Account, LLMCalls, LLMProcesses, LLMDestinations,
          ToolRuns, DistinctTools, ToolsSeen, SampleCmds, LLMLastSeen, ToolLastSeen
```

## ⚙️ Rule Settings

| Setting | Value |
|---------|-------|
| 📛 Name | AI - LLM-Driven Offensive Agent |
| 🔴 Severity | High (overridden by the `Severity` column) |
| ⏱️ Run every / Lookup data from | 1 hour / 3 hours |
| 🎯 Alert threshold | Number of results > 0 |
| 🧾 Event grouping | Trigger an alert for each event |
| 🧩 Entities | Host: `HostName` = `DeviceName` · Account: `Name` = `Account` |
| 📋 Custom details | `LLMProcesses`, `LLMDestinations`, `ToolsSeen`, `ToolRuns`, `SampleCmds` |
| 🏷️ Alert name format | `LLM-driven offensive agent on {{DeviceName}}` |
| 🎚️ Severity column | `Severity` |
| 🗂️ Alert grouping | Group into one incident when **Host** matches, within 24 hours |

## 🛠️ Tuning

- Add approved pentest hosts to `ExcludedDevices`.
- Add your sanctioned AI apps to `SanctionedProcs`.
- On Linux, `RemoteUrl` is often empty, so only Anthropic's IP range (`160.79.104.0/23`) matches. Add other providers' IP ranges if you need them on Linux.
- Two tools trigger Medium; three or more trigger High.

---

## 🧭 Avoiding Duplicate Alerts

The rule runs every hour but looks back 3 hours, so it can correlate LLM calls and tool runs that happen apart. To stop the same activity alerting every hour, it only returns a host when its latest LLM call or tool run was in the last hour. Ongoing activity alerts again, and alert grouping folds those alerts into the same incident.

---

## 🛠️ Creating the Rule in Sentinel

1. Go to **Microsoft Sentinel > Analytics > Create > Scheduled query rule**. In the Defender portal: **Microsoft Sentinel > Configuration > Analytics**.
2. **General:** enter the name and severity from Rule Settings.
3. **Set rule logic:** paste the query. Map entities, add custom details, and set the alert name format and severity column under **Alert details**. Set the schedule and threshold.
4. **Incident settings:** keep incident creation on and set alert grouping from the table.
5. **Automated response:** attach automation rules if you want (for example a notification or enrichment playbook).
6. **Review + create.**

---

## 🧪 Lab Testing

On Kali: `curl -s https://api.anthropic.com/v1/models -o /dev/null`, then run three of the fake tool binaries (`nuclei`, `httpx`, `ffuf`) within the same hour.

Events take up to about 15 minutes to arrive. Run the query in **Logs** first, then wait for the next scheduled run.
