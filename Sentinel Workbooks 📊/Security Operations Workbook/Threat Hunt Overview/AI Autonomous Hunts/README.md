# AI & Autonomous Threats 1.0

A Microsoft Sentinel workbook that tracks LLM API usage and AI-driven attack activity across onboarded devices. It answers four questions: which devices and processes talk to LLM APIs, which of those are unsanctioned, which hosts combine LLM access with offensive tooling, and where AI agent frameworks or local models are being installed.

> **Disclaimer:** This workbook provides visibility for hunting and triage. It does not replace alert triage. Alerts and incidents should still be investigated for deeper analysis.

---

## Parameters

| Parameter | Display Name | Type | Notes |
|---|---|---|---|
| `TimeRange` | Time Range | Time range picker | Default: Last 7 days |
| `DeviceName` | Hostname | Text | Optional. Leave empty for all devices |

Every query starts with `let TargetDevice = trim(" ", "{DeviceName}");` and filters with `isempty(TargetDevice) or DeviceName has TargetDevice`.

---

## Panels

| # | Panel | Visualization | Purpose |
|---|---|---|---|
| 1 | Overview Tiles | Tiles | LLM calls, devices, unsanctioned callers, offensive tool runs, agent hosts |
| 2 | LLM API Calls Over Time | Time chart | Usage trend by provider |
| 3 | LLM Calls by Provider | Pie | Which AI providers are in use |
| 4 | Top LLM API Callers | Grid | Every process calling LLM APIs, sanctioned vs. unsanctioned |
| 5 | Unsanctioned LLM Activity | Grid | Scripts, CLIs and unknown binaries calling LLM APIs |
| 6 | LLM-Driven Offensive Agent | Grid | Hosts with unsanctioned LLM calls **and** offensive tooling |
| 7 | Recon Toolchain Burst | Grid | 3+ offensive tools from one parent within an hour |
| 8 | AI Agent Framework Activity | Grid | Installs of agent frameworks and offensive AI tools |
| 9 | Local LLM Runtimes | Grid | Ollama, LM Studio and llama.cpp running on devices |
| 10 | Inbound Scan & Sweep Bursts | Grid | One source hitting many ports or devices within minutes |
| 11 | Machine-Speed Logon Failures | Grid | Brute force and spraying at machine speed, plus any later success |
| 12 | Web Request Bursts | Grid | Fuzzing, crawling and tool user agents against IIS web servers |
| 13 | WAF Request Bursts | Grid | The same pattern from Azure Application Gateway WAF logs |
| 14 | Machine-Speed Discovery | Grid | 8+ distinct discovery commands from one parent process within 60 seconds |

Panels 10 to 13 cover agents running on the attacker's own infrastructure. Their LLM calls never touch your network, so you detect them by the speed and volume of what reaches you.

---

## 1. Overview Tiles

**Visualization:** Tiles (Title: `Metric`, Left: `Value`)

```kql
let TargetDevice = trim(" ", "{DeviceName}");
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
let LLM = DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
    | extend IsSanctioned = InitiatingProcessFileName in~ (SanctionedProcs);
let ToolRuns = DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ (Tools)
        or (FileName startswith "python" and ProcessCommandLine has "sqlmap");
union
    (LLM | summarize Value = tolong(count()) | extend Metric = "🤖 LLM API Calls", Order = 1),
    (LLM | summarize Value = tolong(dcount(DeviceName)) | extend Metric = "💻 Devices Using LLMs", Order = 2),
    (LLM | where not(IsSanctioned) | summarize Value = tolong(dcount(InitiatingProcessFileName)) | extend Metric = "⚠️ Unsanctioned Callers", Order = 3),
    (ToolRuns | summarize Value = tolong(count()) | extend Metric = "🔎 Offensive Tool Runs", Order = 4),
    (LLM | where not(IsSanctioned) | distinct DeviceId
        | join kind=inner (ToolRuns | distinct DeviceId) on DeviceId
        | summarize Value = tolong(count()) | extend Metric = "🚨 Agent Hosts", Order = 5)
| sort by Order asc
| project Metric, Value
```

---

## 2. LLM API Calls Over Time

**Visualization:** Time chart

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let LLMDomains = dynamic([
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.mistral.ai", "api.groq.com", "openrouter.ai", "api.together.xyz",
    "api.deepseek.com", "api.x.ai", "api.cohere.com", "api.cohere.ai",
    "api.perplexity.ai", "bedrock-runtime"]);
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
| extend Provider = case(
    RemoteUrl has "anthropic" or ipv4_is_in_range(RemoteIP, "160.79.104.0/23"), "Anthropic",
    RemoteUrl has "openai.azure.com", "Azure OpenAI",
    RemoteUrl has "openai", "OpenAI",
    RemoteUrl has "googleapis", "Google",
    RemoteUrl has "mistral", "Mistral",
    RemoteUrl has "groq", "Groq",
    RemoteUrl has "openrouter", "OpenRouter",
    RemoteUrl has "together", "Together",
    RemoteUrl has "deepseek", "DeepSeek",
    RemoteUrl contains "api.x.ai", "xAI",
    RemoteUrl has "cohere", "Cohere",
    RemoteUrl has "perplexity", "Perplexity",
    RemoteUrl has "bedrock", "AWS Bedrock",
    "Other")
| summarize Calls = count() by Provider, bin(TimeGenerated, {TimeRange:grain})
```

---

## 3. LLM Calls by Provider

**Visualization:** Pie chart

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let LLMDomains = dynamic([
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.mistral.ai", "api.groq.com", "openrouter.ai", "api.together.xyz",
    "api.deepseek.com", "api.x.ai", "api.cohere.com", "api.cohere.ai",
    "api.perplexity.ai", "bedrock-runtime"]);
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
| extend Provider = case(
    RemoteUrl has "anthropic" or ipv4_is_in_range(RemoteIP, "160.79.104.0/23"), "Anthropic",
    RemoteUrl has "openai.azure.com", "Azure OpenAI",
    RemoteUrl has "openai", "OpenAI",
    RemoteUrl has "googleapis", "Google",
    RemoteUrl has "mistral", "Mistral",
    RemoteUrl has "groq", "Groq",
    RemoteUrl has "openrouter", "OpenRouter",
    RemoteUrl has "together", "Together",
    RemoteUrl has "deepseek", "DeepSeek",
    RemoteUrl contains "api.x.ai", "xAI",
    RemoteUrl has "cohere", "Cohere",
    RemoteUrl has "perplexity", "Perplexity",
    RemoteUrl has "bedrock", "AWS Bedrock",
    "Other")
| summarize Calls = count() by Provider
| sort by Calls desc
```

---

## 4. Top LLM API Callers

**Visualization:** Grid

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let LLMDomains = dynamic([
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.mistral.ai", "api.groq.com", "openrouter.ai", "api.together.xyz",
    "api.deepseek.com", "api.x.ai", "api.cohere.com", "api.cohere.ai",
    "api.perplexity.ai", "bedrock-runtime"]);
let SanctionedProcs = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "msedgewebview2.exe",
    "claude.exe", "chatgpt.exe", "code.exe", "ms-teams.exe", "teams.exe"]);
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
| extend IsSanctioned = InitiatingProcessFileName in~ (SanctionedProcs)
| summarize Calls = count(),
            Destinations = make_set(coalesce(RemoteUrl, RemoteIP), 5),
            Devices = make_set(DeviceName, 5),
            Accounts = make_set(InitiatingProcessAccountName, 5),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by Process = InitiatingProcessFileName, IsSanctioned
| extend Status = iff(IsSanctioned, "✅ Sanctioned", "⚠️ Unsanctioned")
| sort by IsSanctioned asc, Calls desc
| project Status, Process, Calls, Destinations, Devices, Accounts, FirstSeen, LastSeen
```

---

## 5. Unsanctioned LLM Activity

**Visualization:** Grid

Scripting runtimes and CLI tools calling LLM APIs rank highest, because that's how agents and malware use them.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let LLMDomains = dynamic([
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.mistral.ai", "api.groq.com", "openrouter.ai", "api.together.xyz",
    "api.deepseek.com", "api.x.ai", "api.cohere.com", "api.cohere.ai",
    "api.perplexity.ai", "bedrock-runtime"]);
let SanctionedProcs = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "msedgewebview2.exe",
    "claude.exe", "chatgpt.exe", "code.exe", "ms-teams.exe", "teams.exe"]);
let ScriptRuntimes = dynamic([
    "python", "python3", "python.exe", "pythonw.exe", "node", "node.exe",
    "go", "curl", "curl.exe", "wget", "powershell.exe", "pwsh", "pwsh.exe",
    "bash", "sh", "docker", "containerd-shim"]);
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
| where InitiatingProcessFileName !in~ (SanctionedProcs)
| summarize Calls = count(),
            Destinations = make_set(coalesce(RemoteUrl, RemoteIP), 5),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by DeviceName,
            Account = InitiatingProcessAccountName,
            Process = InitiatingProcessFileName,
            CommandLine = InitiatingProcessCommandLine
| extend SevRank = iff(Process in~ (ScriptRuntimes), 2, 3)
| extend Severity = iff(SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, Calls desc
| project FirstSeen, Severity, Calls, DeviceName, Account, Process, Destinations, CommandLine, LastSeen
```

---

## 6. LLM-Driven Offensive Agent

**Visualization:** Grid

The main signature of an autonomous attack tool: one host makes unsanctioned LLM calls **and** runs offensive tooling. Legitimate activity rarely does both.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
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
let LLMHosts = DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
    | where InitiatingProcessFileName !in~ (SanctionedProcs)
    | summarize LLMCalls = count(),
                LLMProcesses = make_set(InitiatingProcessFileName, 10),
                LLMFirstSeen = min(TimeGenerated),
                LLMLastSeen = max(TimeGenerated)
             by DeviceId, DeviceName;
let ToolHosts = DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ (Tools)
        or (FileName startswith "python" and ProcessCommandLine has "sqlmap")
    | summarize ToolRuns = count(),
                ToolsSeen = make_set(FileName, 20),
                SampleCmds = make_set(ProcessCommandLine, 8),
                ToolLastSeen = max(TimeGenerated)
             by DeviceId;
LLMHosts
| join kind=inner ToolHosts on DeviceId
| extend SevRank = iff(array_length(ToolsSeen) >= 3, 1, 2)
| extend Severity = iff(SevRank == 1, "🔴 Critical", "🟠 High")
| extend Signal = "🤖 LLM-Driven Offensive Agent"
| sort by SevRank asc, ToolRuns desc
| project LLMFirstSeen, Severity, Signal, DeviceName, LLMCalls, LLMProcesses,
          ToolRuns, ToolsSeen, SampleCmds, LLMLastSeen, ToolLastSeen
```

---

## 7. Recon Toolchain Burst

**Visualization:** Grid

Agents chain recon tools quickly from a single parent process. This catches the burst even when the LLM traffic isn't visible.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let Tools = dynamic([
    "httpx", "subfinder", "katana", "ffuf", "nuclei", "naabu", "amass",
    "gobuster", "dnsx", "httprobe", "nmap", "masscan", "sqlmap"]);
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where FileName in~ (Tools)
    or (FileName startswith "python" and ProcessCommandLine has "sqlmap")
| summarize DistinctTools = dcount(FileName),
            ToolsSeen = make_set(FileName, 20),
            Runs = count(),
            SampleCmds = make_set(ProcessCommandLine, 8),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by DeviceName,
            Account = AccountName,
            Parent = InitiatingProcessFileName,
            Window = bin(TimeGenerated, 1h)
| where DistinctTools >= 3
| extend SevRank = iff(DistinctTools >= 5, 1, 2)
| extend Severity = iff(SevRank == 1, "🔴 Critical", "🟠 High")
| sort by SevRank asc, DistinctTools desc, Runs desc
| project FirstSeen, Severity, DistinctTools, ToolsSeen, Runs, DeviceName, Account, Parent, SampleCmds, LastSeen
```

---

## 8. AI Agent Framework Activity

**Visualization:** Grid

Installs of AI agent frameworks and offensive AI tools through pip, npm, git, docker or go. Known offensive AI tools rank highest.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let OffensiveAI = dynamic([
    "artex", "pentestgpt", "pentagi", "hackingbuddygpt", "hexstrike", "villager"]);
let AgentFrameworks = dynamic([
    "langchain", "langgraph", "autogen", "crewai", "open-interpreter",
    "browser-use", "litellm", "anthropic", "openai", "ollama"]);
let InstallVerbs = dynamic([
    "pip install", "pip3 install", "uv add", "uv pip", "npm install", "npm i ",
    "git clone", "docker pull", "docker run", "go install", "go get"]);
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ProcessCommandLine has_any (InstallVerbs)
| where ProcessCommandLine has_any (OffensiveAI) or ProcessCommandLine has_any (AgentFrameworks)
| extend SevRank = iff(ProcessCommandLine has_any (OffensiveAI), 1, 4)
| extend Severity = iff(SevRank == 1, "🔴 Critical", "🔵 Low")
| extend Signal = iff(SevRank == 1, "☠️ Offensive AI Tool", "🧩 Agent Framework")
| summarize Hits = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by Severity, SevRank, Signal, DeviceName, Account = AccountName,
            FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by SevRank asc, LastSeen desc
| project FirstSeen, Severity, Signal, Hits, DeviceName, Account, FileName,
          ProcessCommandLine, InitiatingProcessFileName, LastSeen
```

---

## 9. Local LLM Runtimes

**Visualization:** Grid

Local models make no external API calls, so they won't appear in panels 2 to 6. This shows where they're running.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let Runtimes = dynamic([
    "ollama", "ollama.exe", "ollama app.exe", "llama-server", "llama-server.exe",
    "llama-cli", "lms", "lms.exe", "lm studio.exe", "vllm", "koboldcpp.exe"]);
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where FileName in~ (Runtimes)
| summarize Launches = count(),
            Accounts = make_set(AccountName, 5),
            SampleCmds = make_set(ProcessCommandLine, 5),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by DeviceName, Runtime = FileName
| sort by LastSeen desc
| project FirstSeen, DeviceName, Runtime, Launches, Accounts, SampleCmds, LastSeen
```

---

## 10. Inbound Scan & Sweep Bursts

**Visualization:** Grid

Groups inbound connections by source in 5-minute windows. Includes connections the Windows firewall blocked, which is where most scans land. Internal sources are kept, because an internal host scanning others usually means lateral movement.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let BurstWindow = 5m;
let MinPorts = 10;
let MinTargets = 5;
let Allowlist = dynamic([]);   // approved scanner IPs, e.g. "10.0.0.50"
union
    (DeviceNetworkEvents
        | where TimeGenerated {TimeRange}
        | where ActionType == "InboundConnectionAccepted"
        | project TimeGenerated, DeviceName, RemoteIP, LocalPort, Outcome = "Accepted"),
    (DeviceEvents
        | where TimeGenerated {TimeRange}
        | where ActionType == "FirewallInboundConnectionBlocked"
        | project TimeGenerated, DeviceName, RemoteIP, LocalPort, Outcome = "Blocked")
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where isnotempty(RemoteIP) and RemoteIP !in (Allowlist)
| where RemoteIP !in ("127.0.0.1", "::1")
| summarize Connections = count(),
            Ports = dcount(LocalPort),
            Targets = dcount(DeviceName),
            Blocked = countif(Outcome == "Blocked"),
            SamplePorts = make_set(LocalPort, 15),
            Devices = make_set(DeviceName, 10)
         by RemoteIP, Bucket = bin(TimeGenerated, BurstWindow)
| where Ports >= MinPorts or Targets >= MinTargets or Connections >= 200
| summarize Bursts = count(),
            MaxPorts = max(Ports),
            MaxTargets = max(Targets),
            Connections = sum(Connections),
            Blocked = sum(Blocked),
            SamplePorts = make_set(SamplePorts, 20),
            Devices = make_set(Devices, 10),
            FirstSeen = min(Bucket),
            LastSeen = max(Bucket)
         by RemoteIP
| extend Source = iff(ipv4_is_private(RemoteIP), "🏠 Internal", "🌍 External")
| extend Pattern = case(
    MaxTargets >= MinTargets and MaxPorts >= MinPorts, "🎯 Sweep + Port Scan",
    MaxTargets >= MinTargets, "🌐 Host Sweep",
    MaxPorts >= MinPorts, "🔎 Port Scan",
    "⚡ High Volume")
| extend SevRank = case(
    MaxPorts >= 50 or MaxTargets >= 20, 1,
    MaxPorts >= MinPorts and MaxTargets >= MinTargets, 2,
    Source == "🏠 Internal", 2,
    3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, Connections desc
| project FirstSeen, Severity, Pattern, Source, RemoteIP, Bursts, MaxPorts, MaxTargets,
          Connections, Blocked, SamplePorts, Devices, LastSeen
```

---

## 11. Machine-Speed Logon Failures

**Visualization:** Grid

Failed logons from one source in 5-minute windows. Many accounts means spraying, and many attempts on few accounts means brute force. `Succeeded` flags a source that later logged in successfully, which should be treated as a compromise.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let BurstWindow = 5m;
let MinFailures = 20;
let MinAccounts = 5;
let Allowlist = dynamic([]);
let Successes = DeviceLogonEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType == "LogonSuccess" and isnotempty(RemoteIP)
    | summarize LastSuccess = max(TimeGenerated),
                SuccessAccounts = make_set(AccountName, 5)
             by RemoteIP;
DeviceLogonEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType == "LogonFailed" and isnotempty(RemoteIP)
| where RemoteIP !in (Allowlist) and RemoteIP !in ("127.0.0.1", "::1")
| summarize Failures = count(),
            Accounts = dcount(AccountName),
            SampleAccounts = make_set(AccountName, 10),
            Devices = make_set(DeviceName, 10),
            LogonTypes = make_set(LogonType, 5)
         by RemoteIP, Bucket = bin(TimeGenerated, BurstWindow)
| where Failures >= MinFailures or Accounts >= MinAccounts
| summarize Bursts = count(),
            Failures = sum(Failures),
            MaxAccounts = max(Accounts),
            SampleAccounts = make_set(SampleAccounts, 15),
            Devices = make_set(Devices, 10),
            LogonTypes = make_set(LogonTypes, 5),
            FirstSeen = min(Bucket),
            LastSeen = max(Bucket)
         by RemoteIP
| join kind=leftouter Successes on RemoteIP
| extend Succeeded = isnotempty(LastSuccess) and LastSuccess >= FirstSeen
| extend Pattern = iff(MaxAccounts >= MinAccounts, "🧪 Password Spray", "🔨 Brute Force")
| extend Source = iff(ipv4_is_private(RemoteIP), "🏠 Internal", "🌍 External")
| extend SevRank = case(Succeeded, 1, Failures >= 100 or MaxAccounts >= 20, 2, 3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| extend SuccessAccounts = iff(Succeeded, SuccessAccounts, dynamic([]))
| sort by SevRank asc, Failures desc
| project FirstSeen, Severity, Pattern, Source, RemoteIP, Succeeded, SuccessAccounts,
          Failures, MaxAccounts, SampleAccounts, Devices, LogonTypes, Bursts, LastSeen
```

---

## 12. Web Request Bursts

**Visualization:** Grid  ·  **Requires:** IIS logs in `W3CIISLog` (Azure Monitor Agent)

Per-source request rate on web servers. Many distinct URLs with a high error rate is content fuzzing. Tool and scripting user agents rank higher.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let BurstWindow = 5m;
let MinRequests = 300;
let MinUris = 100;
let Allowlist = dynamic([]);
let ToolAgents = dynamic([
    "python-requests", "python-urllib", "aiohttp", "go-http-client", "curl", "wget",
    "ffuf", "nuclei", "sqlmap", "gobuster", "katana", "httpx", "wfuzz", "nikto",
    "feroxbuster", "dirbuster", "zgrab", "masscan", "headlesschrome", "scrapy"]);
W3CIISLog
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or Computer has TargetDevice
| where isnotempty(cIP) and cIP !in (Allowlist)
| extend Status = tostring(scStatus)
| extend IsToolUA = csUserAgent has_any (ToolAgents)
| summarize Requests = count(),
            Uris = dcount(csUriStem),
            Errors = countif(Status startswith "4"),
            ToolUA = max(toint(IsToolUA)),
            UserAgents = make_set(csUserAgent, 5),
            SampleUris = make_set(csUriStem, 10),
            Sites = make_set(Computer, 5)
         by cIP, Bucket = bin(TimeGenerated, BurstWindow)
| where Requests >= MinRequests or Uris >= MinUris or ToolUA == 1
| summarize Bursts = count(),
            Requests = sum(Requests),
            MaxUris = max(Uris),
            Errors = sum(Errors),
            ToolUA = max(ToolUA),
            UserAgents = make_set(UserAgents, 5),
            SampleUris = make_set(SampleUris, 15),
            Sites = make_set(Sites, 5),
            FirstSeen = min(Bucket),
            LastSeen = max(Bucket)
         by SourceIP = cIP
| extend ErrorRate = round(todouble(Errors) / Requests, 2)
| extend Pattern = case(
    MaxUris >= MinUris and ErrorRate >= 0.5, "📂 Content Fuzzing",
    ToolUA == 1, "🛠️ Tool User-Agent",
    MaxUris >= MinUris, "🕷️ Crawling",
    "⚡ High Volume")
| extend SevRank = case(
    MaxUris >= MinUris and ErrorRate >= 0.5 and ToolUA == 1, 1,
    MaxUris >= MinUris and ErrorRate >= 0.5, 2,
    ToolUA == 1, 2,
    3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, Requests desc
| project FirstSeen, Severity, Pattern, SourceIP, Requests, MaxUris, Errors, ErrorRate,
          UserAgents, SampleUris, Sites, Bursts, LastSeen
```

---

## 13. WAF Request Bursts

**Visualization:** Grid  ·  **Requires:** Application Gateway WAF diagnostics sent to the workspace (`AzureDiagnostics`, category `ApplicationGatewayFirewallLog`)

Sources that set off many WAF rules in a short window. Many distinct rules from one source is automated vulnerability probing.

```kql
let BurstWindow = 5m;
let MinMatches = 50;
let MinRules = 5;
let Allowlist = dynamic([]);
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where Category == "ApplicationGatewayFirewallLog"
| where isnotempty(clientIp_s) and clientIp_s !in (Allowlist)
| summarize Matches = count(),
            Rules = dcount(ruleId_s),
            Blocked = countif(action_s == "Blocked"),
            SampleRules = make_set(strcat(ruleId_s, " ", Message), 10),
            SampleUris = make_set(requestUri_s, 10),
            Hosts = make_set(hostname_s, 5)
         by clientIp_s, Bucket = bin(TimeGenerated, BurstWindow)
| where Matches >= MinMatches or Rules >= MinRules
| summarize Bursts = count(),
            Matches = sum(Matches),
            MaxRules = max(Rules),
            Blocked = sum(Blocked),
            SampleRules = make_set(SampleRules, 15),
            SampleUris = make_set(SampleUris, 15),
            Hosts = make_set(Hosts, 5),
            FirstSeen = min(Bucket),
            LastSeen = max(Bucket)
         by SourceIP = clientIp_s
| extend SevRank = case(MaxRules >= 15, 1, MaxRules >= MinRules, 2, 3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| extend Pattern = iff(MaxRules >= MinRules, "🧨 Automated Probing", "⚡ High Volume")
| sort by SevRank asc, Matches desc
| project FirstSeen, Severity, Pattern, SourceIP, Matches, MaxRules, Blocked,
          SampleRules, SampleUris, Hosts, Bursts, LastSeen
```

---

## 14. Machine-Speed Discovery

**Visualization:** Grid

After a foothold, an agent runs discovery commands far faster than a person types. This panel counts distinct discovery actions per parent process instance in 60-second windows and flags 8 or more. Each `net` subcommand (`net user`, `net group`, `net view`) counts as its own action, and `net1` is merged into `net`.

Windows can split a burst across two minute boundaries, so the query checks two overlapping windowings (offset by 30 seconds) and keeps the stronger one for each parent.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let MinDistinct = 8;
let DiscoveryBins = dynamic([
    // Windows
    "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe",
    "hostname.exe", "tasklist.exe", "quser.exe", "qwinsta.exe", "query.exe", "arp.exe",
    "route.exe", "netstat.exe", "nslookup.exe", "dsquery.exe", "klist.exe", "gpresult.exe",
    "cmdkey.exe", "getmac.exe", "driverquery.exe", "wmic.exe",
    // Linux
    "whoami", "id", "uname", "hostname", "hostnamectl", "ifconfig", "ip", "netstat", "ss",
    "ps", "w", "who", "last", "groups", "env", "printenv", "lsb_release", "arp", "route"]);
let ScriptParents = dynamic([
    "python", "python3", "python.exe", "pythonw.exe", "node", "node.exe", "go",
    "powershell.exe", "pwsh", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "w3wp.exe", "sqlservr.exe", "java", "java.exe", "php", "php-cgi", "httpd", "nginx", "apache2"]);
let ExcludedParents = dynamic([
    "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe", "SenseNdr.exe", "MsMpEng.exe",
    "WaAppAgent.exe", "WindowsAzureGuestAgent.exe", "CollectGuestLogs.exe",
    "IntuneManagementExtension.exe", "AgentExecutor.exe", "CcmExec.exe",
    "mdatp", "wdavdaemon", "waagent", "omsagent", "azuremonitoragent", "telegraf"]);
let Discovery = DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ (DiscoveryBins)
    | where InitiatingProcessFileName !in~ (ExcludedParents)
    | extend Cmd = trim_end(@"\.exe", tolower(FileName))
    | extend Cmd = iff(Cmd == "net1", "net", Cmd)
    | extend Action = iff(Cmd == "net",
        strcat("net ", tolower(extract(@"(?i)net1?(\.exe)?\s+(\w+)", 2, ProcessCommandLine))),
        Cmd)
    | extend ParentKey = strcat(DeviceId, "|", InitiatingProcessId, "|", tostring(InitiatingProcessCreationTime))
    | project TimeGenerated, DeviceName, Account = AccountName, Action, ProcessCommandLine,
              ParentKey, Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
              GrandParent = InitiatingProcessParentFileName;
union
    (Discovery | extend Bucket = bin(TimeGenerated, 1m)),
    (Discovery | extend Bucket = bin(TimeGenerated + 30s, 1m))
| summarize DistinctCmds = dcount(Action),
            Actions = make_set(Action, 30),
            Execs = count(),
            SampleCmds = make_set(ProcessCommandLine, 15),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by ParentKey, DeviceName, Account, Parent, ParentCmd, GrandParent, Bucket
| where DistinctCmds >= MinDistinct
| summarize arg_max(DistinctCmds, *) by ParentKey
| extend SpanSec = datetime_diff("second", LastSeen, FirstSeen)
| extend IsScriptParent = Parent in~ (ScriptParents) or GrandParent in~ (ScriptParents)
| extend SevRank = case(
    DistinctCmds >= 15 or (DistinctCmds >= 10 and IsScriptParent), 1,
    DistinctCmds >= 10 or IsScriptParent, 2,
    3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| extend Signal = "⚡ Machine-Speed Discovery"
| sort by SevRank asc, DistinctCmds desc
| project FirstSeen, Severity, Signal, DistinctCmds, Execs, SpanSec, DeviceName, Account,
          Parent, GrandParent, Actions, ParentCmd, SampleCmds, LastSeen
```

---

## Tuning Notes

- **Sanctioned processes:** Edit `SanctionedProcs` to match the AI apps your organization approves. Anything not on the list appears as unsanctioned.
- **RemoteUrl coverage:** Defender doesn't always populate `RemoteUrl`, especially on Linux. Turning on network protection improves URL coverage on Windows. Anthropic is also matched by its API IP range (`160.79.104.0/23`); other providers rely on the URL.
- **Pentest hosts:** Approved pentest or red team devices will appear in panels 6 to 8. Exclude them by hostname or device tag.
- **Developers:** Panel 8 at Low severity is visibility, not an alert. Developers installing `openai` or `langchain` is normal.
- **Discovery noise:** Login scripts, inventory tools and admin automation can run discovery commands quickly. Add their parent process to `ExcludedParents` in panel 14 rather than raising `MinDistinct`, so real agent bursts still fire.
- **Detection rules:** Panels 6, 7 and 10 to 14 aggregate, so they work as scheduled Sentinel analytic rules rather than Defender custom detections.
- **Burst thresholds:** Each of panels 10 to 13 has its thresholds in `let` statements at the top (`MinPorts`, `MinFailures`, `MinRequests` and so on). Start with the defaults, then raise them if normal traffic shows up.
- **Allowlists:** Add vulnerability scanners, monitoring tools, load balancers and health probes to `Allowlist` in panels 10 to 13, or they'll show as bursts.
- **Blocked inbound connections:** Panel 10 uses `FirewallInboundConnectionBlocked`, which needs Windows Firewall auditing for dropped packets turned on. Without it, the panel only sees accepted connections.
- **Data sources:** Panels 10 and 11 work with Defender data alone. Panels 12 and 13 stay empty unless you collect IIS or Application Gateway WAF logs. If your WAF uses resource-specific tables, switch panel 13 to `AGWFirewallLogs`.