# 🤖 AI Autonomous Threats Hunts

A Microsoft Sentinel workbook that tracks LLM API usage and AI-driven attack activity across onboarded devices. It answers four questions: which devices and processes talk to LLM APIs, which of those are unsanctioned, which hosts combine LLM access with offensive tooling, and where AI agent frameworks or local models are being installed.

> ⚠️ **Disclaimer:** This workbook provides visibility for hunting and triage. It does not replace alert triage. Alerts and incidents should still be investigated for deeper analysis.

---

## 🗂️ Panels

| # | Panel | Visualization | Purpose |
|---|---|---|---|
| 1 | 📊 Overview Tiles | Tiles | LLM calls, devices, unsanctioned callers, offensive tool runs, agent hosts, sensitive files served |
| 2 | 📈 LLM API Calls Over Time | Time chart | Usage trend by provider |
| 3 | ⚠️ Unsanctioned LLM Activity | Grid | Scripts, CLIs and unknown binaries calling LLM APIs |
| 4 | 🤖 LLM-Driven Offensive Agent | Grid | Hosts with unsanctioned LLM calls **and** offensive tooling |
| 5 | 🔎 Recon Toolchain Burst | Grid | 3+ offensive tools from one parent within an hour |
| 6 | 🧩 AI Agent Framework Activity | Grid | Installs of agent frameworks and offensive AI tools |
| 7 | 🌐 Inbound Scan & Sweep Bursts | Grid | One source hitting many ports or devices within minutes |
| 8 | 🔨 Machine-Speed Logon Failures | Grid | Brute force and spraying at machine speed, plus any later success |
| 9 | 🛡️ WAF Request Bursts | Grid | Fuzzing, crawling and tool user agents in Azure Application Gateway WAF logs |
| 10 | ⚡ Machine-Speed Discovery | Grid | 8+ distinct discovery commands from one parent process within 60 seconds |
| 11 | ☁️ Cloud Sign-In Bursts | Grid | Entra ID spraying and brute force at machine speed, plus valid-password and success flags |
| 12 | 🔓 Sensitive Path Probes | Grid | Requests for `/.env`, `/.git/`, cloud keys, configs and backups, and whether any were served |
| 13 | 🔗 Recon to Sign-In | Grid | IPs that probed sensitive paths and then tried to sign in to Entra ID |
| 14 | 🔌 MCP Server Config Changes | Grid | New or changed MCP configs for Claude, Cursor, VS Code and Windsurf, ranked by what wrote them |
| 15 | 🔑 LLM API Key Harvesting | Grid | Searches for LLM API keys, `.env` sweeps, AI credential file access and secret scanners |
| 16 | 🐳 Offensive Containers | Grid | Docker pulling or running offensive AI agents, C2 frameworks and recon toolkits |
| 17 | 🎯 ARTEX Indicator Hits | Grid | Known ARTEX user agents, probe markers, host artifacts, hashes and toolkit domains |
| 18 | 🐚 Web & Database Services Spawning Shells | Grid | IIS, Apache, nginx, Tomcat or SQL Server starting a shell or download tool |
| 19 | 🪪 App & Service Principal Abuse | Grid | Apps assigning themselves roles, adding their own credentials, or having secrets guessed |
| 20 | ⏱️ Fixed-Rhythm Password Spray | Grid | Sprays sent at a steady machine rhythm, scored by how regular the gaps are |
| 21 | 📞 Callbacks to Webhook, OAST & Tunnel Services | Grid | Hosts reaching interactsh, webhook bins, DNS loggers, ngrok or Cloudflare tunnels |

Panels 7 to 9 and 11 to 13 cover agents running on the attacker's own infrastructure. Their LLM calls never touch your network, so you detect them by the speed and volume of what reaches you.

---

## 📊 1. Overview Tiles

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
    | where ActionType in ("ConnectionSuccess", "ConnectionRequest")   // Linux logs outbound as ConnectionRequest
    | where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
    | extend IsSanctioned = InitiatingProcessFileName in~ (SanctionedProcs);
let ToolRuns = DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ (Tools)
        or (FileName startswith "python" and ProcessCommandLine has "sqlmap");
let SensitivePaths = @"(?i)(/\.env|/\.git(/|$)|/\.aws/|/\.ssh/|/\.svn/|/\.hg/|/\.ds_store|/\.htpasswd|/\.htaccess|/\.npmrc|/\.dockercfg|/\.docker/|/\.vscode/|/\.idea/|/\.kube/|wp-config\.php|/config\.(php|json|ya?ml|ini)|/web\.config|/appsettings(\.\w+)?\.json|/phpinfo|/server-status|/actuator|/docker-compose\.ya?ml|id_rsa|\.(sql|bak|old|backup|swp|tar|tgz|zip)$|/backup)";
union isfuzzy=true
    (LLM | summarize Value = tolong(count()) | extend Metric = "🤖 LLM API Calls", Order = 1),
    (LLM | summarize Value = tolong(dcount(DeviceName)) | extend Metric = "💻 Devices Using LLMs", Order = 2),
    (LLM | where not(IsSanctioned) | summarize Value = tolong(dcount(InitiatingProcessFileName)) | extend Metric = "⚠️ Unsanctioned Callers", Order = 3),
    (ToolRuns | summarize Value = tolong(count()) | extend Metric = "🔎 Offensive Tool Runs", Order = 4),
    (LLM | where not(IsSanctioned) | distinct DeviceId
        | join kind=inner (ToolRuns | distinct DeviceId) on DeviceId
        | summarize Value = tolong(count()) | extend Metric = "🚨 Agent Hosts", Order = 5),
    (W3CIISLog
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or Computer has TargetDevice
        | where csUriStem matches regex SensitivePaths
        | where scStatus startswith "2"
        | summarize Value = tolong(count()) | extend Metric = "🔓 Sensitive Files Served", Order = 6)
| sort by Order asc
| project Metric, Value
```

---

## 📈 2. LLM API Calls Over Time

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
| where ActionType in ("ConnectionSuccess", "ConnectionRequest")   // Linux logs outbound as ConnectionRequest
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

## ⚠️ 3. Unsanctioned LLM Activity

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
| where ActionType in ("ConnectionSuccess", "ConnectionRequest")   // Linux logs outbound as ConnectionRequest
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

## 🤖 4. LLM-Driven Offensive Agent

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
    | where ActionType in ("ConnectionSuccess", "ConnectionRequest")   // Linux logs outbound as ConnectionRequest
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

## 🔎 5. Recon Toolchain Burst

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

## 🧩 6. AI Agent Framework Activity

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

## 🌐 7. Inbound Scan & Sweep Bursts

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

## 🔨 8. Machine-Speed Logon Failures

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

## 🛡️ 9. WAF Request Bursts

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

## ⚡ 10. Machine-Speed Discovery

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

## ☁️ 11. Cloud Sign-In Bursts

**Visualization:** Grid  ·  **Data:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`

Failed Entra ID sign-ins from one IP in 5-minute windows, across interactive and non-interactive sign-ins. Many accounts means spraying, and many attempts on few accounts means brute force.

- **Valid password:** result codes such as "MFA required" or "blocked by Conditional Access" mean the attacker had the right password. `ValidPwUsers` lists those accounts, and the row ranks **High**.
- **Succeeded:** the IP later signed in successfully, so the row ranks **Critical**.

```kql
let BurstWindow = 5m;
let MinFailures = 20;
let MinUsers = 5;
let Allowlist = dynamic([]);   // corporate egress IPs, VPN gateways
let FailCodes = dynamic(["50126", "50053", "50034", "50055", "50056", "50057", "50064"]);
let ValidPwCodes = dynamic(["50072", "50074", "50076", "50079", "50158", "53003"]);
let Signins = union
    (SigninLogs
        | where TimeGenerated {TimeRange}
        | project TimeGenerated, UserPrincipalName, IPAddress, ResultType = tostring(ResultType),
                  AppDisplayName, UserAgent, ASN = tostring(AutonomousSystemNumber), Location = tostring(Location)),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated {TimeRange}
        | project TimeGenerated, UserPrincipalName, IPAddress, ResultType = tostring(ResultType),
                  AppDisplayName, UserAgent, ASN = tostring(AutonomousSystemNumber), Location = tostring(Location))
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | where isnotempty(IPAddress) and IPAddress !in (Allowlist);
let Successes = Signins
    | where ResultType == "0"
    | summarize LastSuccess = max(TimeGenerated),
                SuccessUsers = make_set(UserPrincipalName, 5)
             by IPAddress;
Signins
| where ResultType in (FailCodes) or ResultType in (ValidPwCodes)
| summarize Failures = countif(ResultType in (FailCodes)),
            ValidPw = countif(ResultType in (ValidPwCodes)),
            Users = dcount(UserPrincipalName),
            SampleUsers = make_set(UserPrincipalName, 10),
            ValidPwUsers = make_set_if(UserPrincipalName, ResultType in (ValidPwCodes), 10),
            Apps = make_set(AppDisplayName, 5),
            UserAgents = make_set(UserAgent, 5),
            Location = take_any(Location),
            ASN = take_any(ASN)
         by IPAddress, Bucket = bin(TimeGenerated, BurstWindow)
| where Failures >= MinFailures or Users >= MinUsers
| summarize Bursts = count(),
            Failures = sum(Failures),
            ValidPw = sum(ValidPw),
            MaxUsers = max(Users),
            SampleUsers = make_set(SampleUsers, 15),
            ValidPwUsers = make_set(ValidPwUsers, 10),
            Apps = make_set(Apps, 5),
            UserAgents = make_set(UserAgents, 5),
            Location = take_any(Location),
            ASN = take_any(ASN),
            FirstSeen = min(Bucket),
            LastSeen = max(Bucket)
         by IPAddress
| join kind=leftouter Successes on IPAddress
| extend Succeeded = isnotempty(LastSuccess) and LastSuccess >= FirstSeen
| extend SuccessUsers = iff(Succeeded, SuccessUsers, dynamic([]))
| extend Pattern = iff(MaxUsers >= MinUsers, "🧪 Password Spray", "🔨 Brute Force")
| extend SevRank = case(Succeeded, 1, ValidPw > 0, 2, Failures >= 100 or MaxUsers >= 20, 2, 3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, Failures desc
| project FirstSeen, Severity, Pattern, IPAddress, Location, ASN, Succeeded, SuccessUsers,
          ValidPwUsers, Failures, MaxUsers, SampleUsers, Apps, UserAgents, Bursts, LastSeen
```

---

## 🔓 12. Sensitive Path Probes

**Visualization:** Grid  ·  **Requires:** IIS logs in `W3CIISLog` (Azure Monitor Agent)

Requests for files that should never be public: `/.env`, `/.git/`, cloud and SSH keys, app configs, backups and debug endpoints. Offensive AI agents check these within minutes of finding a site. Any **served** (2xx) path ranks Critical, because secrets may already be exposed.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let MinPaths = 10;          // distinct sensitive paths for a machine-speed sweep
let SweepMinutes = 10;
let Allowlist = dynamic([]);   // approved vulnerability scanners
let SensitivePaths = @"(?i)(/\.env|/\.git(/|$)|/\.aws/|/\.ssh/|/\.svn/|/\.hg/|/\.ds_store|/\.htpasswd|/\.htaccess|/\.npmrc|/\.dockercfg|/\.docker/|/\.vscode/|/\.idea/|/\.kube/|wp-config\.php|/config\.(php|json|ya?ml|ini)|/web\.config|/appsettings(\.\w+)?\.json|/phpinfo|/server-status|/actuator|/docker-compose\.ya?ml|id_rsa|\.(sql|bak|old|backup|swp|tar|tgz|zip)$|/backup)";
W3CIISLog
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or Computer has TargetDevice
| where isnotempty(cIP) and cIP !in (Allowlist)
| where csUriStem matches regex SensitivePaths
| extend Status = tostring(scStatus)
| extend Category = case(
    csUriStem matches regex @"(?i)/\.(env|aws|ssh|npmrc|docker|dockercfg|kube)|id_rsa|\.htpasswd", "🔑 Secrets",
    csUriStem matches regex @"(?i)/\.(git|svn|hg)", "🧬 Source Control",
    csUriStem matches regex @"(?i)\.(sql|bak|old|backup|swp|tar|tgz|zip)$|/backup", "💾 Backups",
    csUriStem matches regex @"(?i)phpinfo|server-status|actuator", "🩺 Debug/Admin",
    "⚙️ Config")
| summarize Requests = count(),
            DistinctPaths = dcount(csUriStem),
            Served = countif(Status startswith "2"),
            ServedPaths = make_set_if(csUriStem, Status startswith "2", 20),
            Categories = make_set(Category),
            SamplePaths = make_set(csUriStem, 20),
            UserAgents = make_set(csUserAgent, 5),
            Sites = make_set(Computer, 5),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by SourceIP = cIP
| extend DurationMin = datetime_diff("minute", LastSeen, FirstSeen)
| extend Pattern = case(
    Served > 0, "🔓 File Served",
    DistinctPaths >= MinPaths and DurationMin <= SweepMinutes, "⚡ Machine-Speed Sweep",
    DistinctPaths >= 5, "🔍 Targeted Probe",
    "👀 Single Probe")
| extend SevRank = case(
    Served > 0, 1,
    DistinctPaths >= MinPaths and DurationMin <= SweepMinutes, 2,
    DistinctPaths >= 5, 3,
    4)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", SevRank == 3, "🟡 Medium", "🔵 Low")
| sort by SevRank asc, DistinctPaths desc
| project FirstSeen, Severity, Pattern, SourceIP, Served, ServedPaths, DistinctPaths, Requests,
          DurationMin, Categories, SamplePaths, UserAgents, Sites, LastSeen
```

---

## 🔗 13. Recon to Sign-In

**Visualization:** Grid  ·  **Requires:** IIS logs in `W3CIISLog` plus Entra ID sign-in logs

IPs that probed sensitive paths and **then** tried to sign in to Entra ID. This is the chain an agent runs after finding credentials in an exposed file: recon, harvest, log in. Pair it with a decoy `/.env` holding honeytoken credentials to catch it in the act.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let Allowlist = dynamic([]);   // corporate egress IPs, approved scanners
let ValidPwCodes = dynamic(["50072", "50074", "50076", "50079", "50158", "53003"]);
let SensitivePaths = @"(?i)(/\.env|/\.git(/|$)|/\.aws/|/\.ssh/|/\.svn/|/\.hg/|/\.ds_store|/\.htpasswd|/\.htaccess|/\.npmrc|/\.dockercfg|/\.docker/|/\.vscode/|/\.idea/|/\.kube/|wp-config\.php|/config\.(php|json|ya?ml|ini)|/web\.config|/appsettings(\.\w+)?\.json|/phpinfo|/server-status|/actuator|/docker-compose\.ya?ml|id_rsa|\.(sql|bak|old|backup|swp|tar|tgz|zip)$|/backup)";
let Probers = W3CIISLog
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or Computer has TargetDevice
    | where isnotempty(cIP) and cIP !in (Allowlist)
    | where csUriStem matches regex SensitivePaths
    | summarize FirstProbe = min(TimeGenerated),
                ProbedPaths = dcount(csUriStem),
                Served = countif(tostring(scStatus) startswith "2"),
                SamplePaths = make_set(csUriStem, 15),
                Sites = make_set(Computer, 5)
             by IPAddress = cIP;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated {TimeRange}
| where IPAddress in ((Probers | project IPAddress))
| lookup kind=inner (Probers | project IPAddress, FirstProbe) on IPAddress
| where TimeGenerated >= FirstProbe
| summarize SignIns = count(),
            Successes = countif(ResultType == "0"),
            ValidPw = countif(ResultType in (ValidPwCodes)),
            Users = make_set(UserPrincipalName, 20),
            SuccessUsers = make_set_if(UserPrincipalName, ResultType == "0", 10),
            Apps = make_set(AppDisplayName, 10),
            FirstSignIn = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
         by IPAddress
| lookup kind=inner Probers on IPAddress
| extend MinutesToSignIn = datetime_diff("minute", FirstSignIn, FirstProbe)
| extend Pattern = case(
    Successes > 0, "🔓 Probe → Successful Sign-In",
    ValidPw > 0, "🔑 Probe → Valid Password",
    "🔁 Probe → Failed Sign-In")
| extend SevRank = case(Successes > 0, 1, ValidPw > 0 or Served > 0, 2, 3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, MinutesToSignIn asc
| project FirstProbe, Severity, Pattern, IPAddress, MinutesToSignIn, Served, ProbedPaths,
          SamplePaths, SignIns, Successes, SuccessUsers, ValidPw, Users, Apps, Sites, FirstSignIn, LastSeen
```

---

## 🔌 14. MCP Server Config Changes

**Visualization:** Grid

New or changed MCP (Model Context Protocol) config files for Claude Desktop, Claude Code, Cursor, VS Code and Windsurf. An attacker who adds a malicious MCP server gets a tool that runs every time the user's AI app starts. A change written by a shell or script ranks higher than one made by the AI app or editor itself.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let McpFiles = dynamic(["claude_desktop_config.json", "mcp.json", ".mcp.json", "mcp_config.json"]);
let McpFolders = @"(?i)[\\/](Claude|\.claude|\.cursor|\.vscode|Code|windsurf|\.codeium)[\\/]";
let AppProcs = dynamic([
    "claude.exe", "claude", "cursor.exe", "cursor", "code.exe", "code", "windsurf.exe", "windsurf",
    "explorer.exe", "notepad.exe", "notepad++.exe", "vim", "nano", "gedit"]);
let ScriptProcs = dynamic([
    "powershell.exe", "pwsh.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "python.exe", "python3", "python", "node.exe", "node", "bash", "sh", "zsh", "curl", "wget"]);
DeviceFileEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName =~ ".mcp.json"                                    // Claude Code project-level config, any folder
    or (FileName in~ (McpFiles) and FolderPath matches regex McpFolders)
| extend Writer = tolower(InitiatingProcessFileName)
| extend WriterType = case(
    Writer in~ (ScriptProcs), "🐚 Shell / Script",
    Writer in~ (AppProcs), "🧩 AI App / Editor",
    "❓ Other Process")
| extend SevRank = case(WriterType has "Shell", 2, WriterType has "Other", 3, 4)
| extend Severity = case(SevRank == 2, "🟠 High", SevRank == 3, "🟡 Medium", "🔵 Low")
| sort by SevRank asc, TimeGenerated desc
| project TimeGenerated, Severity, WriterType, DeviceName, ActionType, FolderPath,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
```

---

## 🔑 15. LLM API Key Harvesting

**Visualization:** Grid

Searches for LLM API keys and AI tool credentials. Stolen keys feed "LLMjacking" (running an attacker's workload on your AI account) and give an agent its own model access. Four patterns:

- **Key search:** grep, findstr or Select-String looking for key prefixes or key variable names
- **Env file sweep:** recursive searches for `.env` files across a disk
- **AI credential file access:** shell tools reading, copying, encoding or uploading Claude, Codex or Copilot credential files
- **Secret scanner:** tools like trufflehog or gitleaks, which attackers also use

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let KeyPrefixes = @"sk-(ant|proj|or)-";
let KeyNames = dynamic([
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY", "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY", "XAI_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY"]);
let SearchTools = dynamic(["grep", "egrep", "rg", "ag", "ack", "findstr.exe", "strings", "awk"]);
let SecretScanners = dynamic(["trufflehog", "trufflehog.exe", "gitleaks", "gitleaks.exe", "noseyparker", "detect-secrets"]);
let AiCredFiles = @"(?i)\.claude[\\/]\.credentials\.json|\.codex[\\/]auth\.json|github-copilot[\\/](hosts|apps)\.json";
let ReadTools = dynamic(["cat", "cp", "scp", "tar", "zip", "base64", "curl", "wget", "xxd",
    "type", "copy", "xcopy", "robocopy", "certutil.exe", "powershell.exe", "pwsh.exe", "pwsh"]);
let ExcludedAccounts = dynamic([]);   // approved secret-scanning service accounts
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where AccountName !in~ (ExcludedAccounts)
| extend Cmd = ProcessCommandLine, Proc = tolower(FileName)
| extend HasKey = Cmd has_any (KeyNames) or Cmd matches regex KeyPrefixes
| extend Pattern = case(
    Proc in~ (SearchTools) and HasKey, "🔍 Key Search",
    Proc in~ ("powershell.exe", "pwsh.exe", "pwsh") and Cmd has "Select-String" and HasKey, "🔍 Key Search",
    Proc in~ ("find", "fd") and Cmd matches regex @"-name\s+['""]?\*?\.env\b", "🗂️ Env File Sweep",
    Cmd has_any ("Get-ChildItem", "gci") and Cmd has "Recurse" and Cmd contains ".env", "🗂️ Env File Sweep",
    Proc in~ (ReadTools) and Cmd matches regex AiCredFiles, "🪪 AI Credential File Access",
    Proc in~ (SecretScanners), "🧪 Secret Scanner",
    "")
| where isnotempty(Pattern)
| extend SevRank = case(Pattern has "Credential", 1, Pattern has_any ("Key Search", "Env File"), 2, 3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, TimeGenerated desc
| project TimeGenerated, Severity, Pattern, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

---

## 🐳 16. Offensive Containers

**Visualization:** Grid

Docker or Podman pulling or running offensive images: recon toolkits, C2 frameworks and offensive AI agents. ARTEX-style agents run in containers, so the container launch is often the clearest host-level signal. A host that also makes unsanctioned LLM calls ranks Critical.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let ContainerCli = dynamic(["docker", "docker.exe", "podman", "podman.exe", "nerdctl", "docker-compose", "docker-compose.exe"]);
let AgentImages = @"artex|scopeweaver|scopesentry|pentestgpt|hexstrike";
let C2Images = @"sliver|bcsecurity|mythic|havoc|covenant|metasploit";
let ReconImages = @"kalilinux/kali|kali-rolling|parrotsec/|blackarchlinux|projectdiscovery/|instrumentisto/nmap|sqlmapproject|frapsoft/nikto|trickest/|zaproxy";
let LLMDomains = dynamic([
    "api.anthropic.com", "api.openai.com", "openai.azure.com", "generativelanguage.googleapis.com",
    "api.mistral.ai", "api.groq.com", "openrouter.ai", "api.deepseek.com", "api.x.ai"]);
let SanctionedProcs = dynamic(["msedge.exe", "chrome.exe", "firefox.exe", "claude.exe", "chatgpt.exe", "code.exe"]);
let LLMHosts = DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("ConnectionSuccess", "ConnectionRequest")   // Linux logs outbound as ConnectionRequest
    | where RemoteUrl has_any (LLMDomains) or ipv4_is_in_range(RemoteIP, "160.79.104.0/23")
    | where InitiatingProcessFileName !in~ (SanctionedProcs)
    | distinct DeviceId;
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where FileName in~ (ContainerCli)
| where ProcessCommandLine has_any ("pull", "run", "create", "compose", "up", "build")
| extend Cmd = tolower(ProcessCommandLine)
| extend Category = case(
    Cmd matches regex AgentImages, "🤖 Offensive AI Agent",
    Cmd matches regex C2Images, "📡 C2 Framework",
    Cmd matches regex ReconImages, "🔎 Recon Toolkit",
    "")
| where isnotempty(Category)
| extend LLMHost = DeviceId in (LLMHosts)
| extend SevRank = case(LLMHost, 1, Category has_any ("Agent", "C2"), 2, 3)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, TimeGenerated desc
| project TimeGenerated, Severity, Category, LLMHost, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

---

## 🎯 17. ARTEX Indicator Hits

**Visualization:** Grid

Known ARTEX markers across web, sign-in and endpoint data: user agents that name ARTEX or its forks, probe paths and markers, host artifacts, file hashes, backdoored container images and toolkit domains. Indicators come from the [ThreatDefence ARTEX detections](https://github.com/ThreatDefence/artex-detections) project. Host artifacts, hashes and domains rank Critical, because they mean the activity reached a host.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let UAHigh   = @"(?i)artex|scopeweaver|spa-api-recon";
let UAMedium = @"(?i)hexstrike|cyberstrikeai|reconprobe/1\.0|norma/0\.4|azure-toolkit/1\.0";
let WebMarkers = @"(?i)zzz-nonexistent-xyz123|zzz_nonexistent_abc\.txt|notexist-xyz|artex[_-]?probe|artex_write_probe|artx_persist_ok|artex_control_marker_zz9q|%artex_probe_unset%|callback\?code=aaaa&state=notvalidb64|eyjhbgcioijub25lin0\.";
let HostPaths = @"(?i)artex-probe-|\\programdata\\artx5v\\|zzartx0000\.php|[\\/](cl1217|f1219a|z1219)\.jsp$|graphics-hook-filter64\.dll|graphics-hook_config\.bin";
let CmdMarkers = @"(?i)artex-probe-|artexprobe|\\programdata\\artx5v|art18-|artex_write_probe|artx_persist_ok|artex_control_marker_zz9q|tomicdd/artex|congdonglinux/artex|microsoftedgeupdatetaskmachine(ua|core)\{(cec15d9b|4c33ce3f)|microsoft_updates";
let Hashes = dynamic([
    "49fe70419fd19b81ca8d730a6ef7c1ec71b681d60b390761070d42686c7d2068",
    "3fb5a9fb3e2cb1d6208966bd4e55d10282d19c7250d827efa560463d60a12ee4",
    "364251838edfcf5ef1107fa692da3c5bd9a540482449f645992830134bf807ab",
    "3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0",
    "2a23e10bfc097e98295cbff8124bd403c4cb677e709b48ccc53d6aca216c3061",
    "da4128aa5d006e05c58f0d240c2d8e5fb02774b6acf314f1230059c7a3498724",
    "d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573"]);
let Domains = dynamic(["nginxmysql.com", "sqlserver-sqlite.com", "ddduuuppp.com",
    "vietnam852.com", "zhzy999.net", "jiancai008.com"]);
union isfuzzy=true
    (W3CIISLog
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or Computer has TargetDevice
        | extend Request = strcat(csUriStem, "?", csUriQuery)
        | where csUserAgent matches regex UAHigh or csUserAgent matches regex UAMedium or Request matches regex WebMarkers
        | project TimeGenerated, Source = "🌐 IIS", Entity = cIP, Host = Computer,
                  Indicator = iff(Request matches regex WebMarkers, "Web probe marker", "User agent"),
                  Detail = iff(Request matches regex WebMarkers, Request, csUserAgent), Rank = iff(csUserAgent matches regex UAMedium and not(Request matches regex WebMarkers), 3, 2)),
    (AzureDiagnostics
        | where TimeGenerated {TimeRange}
        | where Category == "ApplicationGatewayAccessLog"
        | where userAgent_s matches regex UAHigh or userAgent_s matches regex UAMedium or requestUri_s matches regex WebMarkers
        | project TimeGenerated, Source = "🛡️ App Gateway", Entity = clientIP_s, Host = host_s,
                  Indicator = iff(requestUri_s matches regex WebMarkers, "Web probe marker", "User agent"),
                  Detail = iff(requestUri_s matches regex WebMarkers, requestUri_s, userAgent_s), Rank = 2),
    (union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
        | where TimeGenerated {TimeRange}
        | where UserAgent matches regex UAHigh or UserAgent matches regex UAMedium
        | project TimeGenerated, Source = "🔐 Entra Sign-in", Entity = IPAddress, Host = UserPrincipalName,
                  Indicator = "User agent", Detail = UserAgent, Rank = 2),
    (DeviceFileEvents
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or DeviceName has TargetDevice
        | where FolderPath matches regex HostPaths or SHA256 in (Hashes)
        | project TimeGenerated, Source = "💻 File", Entity = InitiatingProcessAccountName, Host = DeviceName,
                  Indicator = iff(SHA256 in (Hashes), "File hash", "Host artifact"), Detail = FolderPath, Rank = 1),
    (DeviceProcessEvents
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or DeviceName has TargetDevice
        | where ProcessCommandLine matches regex CmdMarkers or SHA256 in (Hashes) or FolderPath endswith "/app/artex"
        | project TimeGenerated, Source = "⚙️ Process", Entity = AccountName, Host = DeviceName,
                  Indicator = iff(SHA256 in (Hashes), "File hash", "Command marker"), Detail = ProcessCommandLine, Rank = 1),
    (DeviceNetworkEvents
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or DeviceName has TargetDevice
        | where RemoteUrl has_any (Domains)
        | project TimeGenerated, Source = "📡 Network", Entity = RemoteIP, Host = DeviceName,
                  Indicator = "Toolkit / C2 domain", Detail = strcat(RemoteUrl, " <- ", InitiatingProcessFileName), Rank = 1)
| extend Severity = case(Rank == 1, "🔴 Critical", Rank == 2, "🟠 High", "🟡 Medium")
| summarize Hits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Samples = make_set(Detail, 5)
         by Severity, Rank, Source, Indicator, Entity, Host
| sort by Rank asc, LastSeen desc
| project FirstSeen, Severity, Source, Indicator, Entity, Host, Hits, Samples, LastSeen
```

---

## 🐚 18. Web & Database Services Spawning Shells

**Visualization:** Grid

A web server (IIS, Apache, nginx, PHP, Tomcat) or database (SQL Server, MySQL, PostgreSQL) starting a shell, script host or download and recon tool. That's the moment an attack on an application becomes code running on the server: a web shell, an injection, or `xp_cmdshell`. ARTEX operators brute-force SQL Servers and run payloads this way.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let WebParents = dynamic(["w3wp.exe", "iisexpress.exe", "httpd.exe", "httpd", "apache2", "nginx.exe", "nginx",
    "php-cgi.exe", "php-fpm", "tomcat.exe", "tomcat9.exe", "java.exe", "java"]);
let DbParents = dynamic(["sqlservr.exe", "mysqld.exe", "mysqld", "postgres.exe", "postgres", "oracle.exe", "mongod.exe", "mongod"]);
let Shells = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "wscript.exe", "cscript.exe", "mshta.exe",
    "bash", "sh", "dash", "zsh"]);
let Tools = dynamic(["certutil.exe", "bitsadmin.exe", "curl.exe", "curl", "wget", "whoami.exe", "whoami", "net.exe", "net1.exe",
    "nltest.exe", "systeminfo.exe", "tasklist.exe", "schtasks.exe", "rundll32.exe", "regsvr32.exe",
    "nc", "ncat", "netcat", "python", "python3", "perl"]);
let ExcludedCmds = dynamic([]);   // known-good command fragments, e.g. a monitoring script
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where InitiatingProcessFileName in~ (WebParents) or InitiatingProcessFileName in~ (DbParents)
| where FileName in~ (Shells) or FileName in~ (Tools)
| where not(ProcessCommandLine has_any (ExcludedCmds))
| extend Service = iff(InitiatingProcessFileName in~ (DbParents), "🗄️ Database", "🌐 Web")
| extend Child = iff(FileName in~ (Tools), "🧰 Download / Recon Tool", "🐚 Shell")
| extend SevRank = case(Service has "Database", 1, Child has "Tool", 1, InitiatingProcessFileName in~ ("java.exe", "java"), 3, 2)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", "🟡 Medium")
| sort by SevRank asc, TimeGenerated desc
| project TimeGenerated, Severity, Service, Child, DeviceName, InitiatingProcessFileName, FileName,
          ProcessCommandLine, AccountName, InitiatingProcessCommandLine
```

---

## 🪪 19. App & Service Principal Abuse

**Visualization:** Grid

Apps and service principals abusing their own access in Entra ID: assigning themselves roles, adding their own credentials, or having their client secret guessed until it works. Attackers who take over an app get access that MFA and Conditional Access for users don't touch.

```kql
let MinSecretFailures = 5;
let RoleOps = dynamic(["Add app role assignment to service principal", "Add member to role", "Add eligible member to role"]);
let SecretFailCodes = dynamic(["7000215", "7000222"]);   // invalid / expired client secret
union isfuzzy=true
    (AuditLogs
        | where TimeGenerated {TimeRange}
        | where OperationName in (RoleOps)
            or OperationName has "Certificates and secrets management"
            or OperationName == "Add service principal credentials"
        | extend InitiatorSpId = tostring(InitiatedBy.app.servicePrincipalId),
                 InitiatorApp = tostring(InitiatedBy.app.displayName),
                 InitiatorUser = tostring(InitiatedBy.user.userPrincipalName),
                 TargetName = tostring(TargetResources[0].displayName)
        | extend ByApp = isnotempty(InitiatorSpId)
        | extend Self = ByApp and (tostring(TargetResources) has InitiatorSpId or TargetName == InitiatorApp)
        | extend IsRole = OperationName in (RoleOps)
        | extend Pattern = case(
            IsRole and Self, "👑 App Assigned Itself a Role",
            not(IsRole) and Self, "🔑 App Added Its Own Credential",
            IsRole and ByApp, "🧩 App Granted a Role",
            ByApp, "🔑 App Added a Credential",
            "👤 User Added an App Credential")
        | extend SevRank = case(Pattern has "Itself", 1, Pattern has "Its Own", 2, ByApp, 3, 4)
        | project TimeGenerated, SevRank, Pattern, ServicePrincipal = coalesce(InitiatorApp, TargetName),
                  Actor = coalesce(InitiatorApp, InitiatorUser), Target = TargetName, IPAddress = "",
                  Detail = OperationName, Count = 1),
    (AADServicePrincipalSignInLogs
        | where TimeGenerated {TimeRange}
        | summarize Failures = countif(ResultType in (SecretFailCodes)),
                    Successes = countif(ResultType == "0"),
                    FirstFailure = minif(TimeGenerated, ResultType in (SecretFailCodes)),
                    LastSuccess = maxif(TimeGenerated, ResultType == "0"),
                    Resources = make_set(ResourceDisplayName, 10)
                 by ServicePrincipalName, ServicePrincipalId, IPAddress
        | where Failures >= MinSecretFailures
        | extend Cracked = Successes > 0 and LastSuccess > FirstFailure
        | extend Pattern = iff(Cracked, "🔓 Secret Guessing Then Success", "🎲 Secret Guessing")
        | project TimeGenerated = FirstFailure, SevRank = iff(Cracked, 1, 3), Pattern,
                  ServicePrincipal = ServicePrincipalName, Actor = IPAddress, Target = strcat_array(Resources, ", "),
                  IPAddress, Detail = strcat(Failures, " bad secrets, ", Successes, " successes"), Count = Failures)
| extend Severity = case(SevRank == 1, "🔴 Critical", SevRank == 2, "🟠 High", SevRank == 3, "🟡 Medium", "🔵 Low")
| sort by SevRank asc, TimeGenerated desc
| project TimeGenerated, Severity, Pattern, ServicePrincipal, Actor, Target, IPAddress, Detail, Count
```

---

## ⏱️ 20. Fixed-Rhythm Password Spray

**Visualization:** Grid

Password sprays sent at a steady machine rhythm, such as one attempt every second. Humans and most retry logic are irregular; a script or agent is not. The `Rhythm` score is the spread of gaps between attempts divided by the average gap: the closer to 0, the more machine-like. Complements panel 11, which looks at volume.

```kql
let MinAttempts = 20;
let MinUsers = 5;
let Allowlist = dynamic([]);   // corporate egress IPs
let FailCodes = dynamic(["50126", "50053", "50055", "50057"]);
SigninLogs
| where TimeGenerated {TimeRange}
| where ResultType in (FailCodes)
| where isnotempty(IPAddress) and IPAddress !in (Allowlist)
| extend Window = bin(TimeGenerated, 1h)
| project TimeGenerated, Window, IPAddress, UserPrincipalName, UserAgent, AppDisplayName
| sort by IPAddress asc, Window asc, TimeGenerated asc
| extend GapSec = iff(prev(IPAddress) == IPAddress and prev(Window) == Window,
                      datetime_diff("millisecond", TimeGenerated, prev(TimeGenerated)) / 1000.0, real(null))
| summarize Attempts = count(), Users = dcount(UserPrincipalName),
            AvgGapSec = round(avg(GapSec), 2), GapStdev = round(stdev(GapSec), 2),
            SampleUsers = make_set(UserPrincipalName, 15), UserAgents = make_set(UserAgent, 5),
            Apps = make_set(AppDisplayName, 5), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
         by IPAddress, Window
| where Attempts >= MinAttempts and Users >= MinUsers
| extend Rhythm = iff(AvgGapSec > 0, round(GapStdev / AvgGapSec, 2), real(null))
| extend Pattern = case(Rhythm <= 0.2, "⏱️ Machine Rhythm", Rhythm <= 0.5, "🔁 Scripted", "👤 Irregular")
| extend SevRank = case(Pattern has "Machine", 2, Pattern has "Scripted", 3, 4)
| extend Severity = case(SevRank == 2, "🟠 High", SevRank == 3, "🟡 Medium", "🔵 Low")
| sort by SevRank asc, Attempts desc
| project FirstSeen, Severity, Pattern, IPAddress, Attempts, Users, AvgGapSec, Rhythm,
          SampleUsers, UserAgents, Apps, LastSeen
```

---

## 📞 21. Callbacks to Webhook, OAST & Tunnel Services

**Visualization:** Grid

Hosts reaching out-of-band testing services (webhook bins, interactsh and Burp Collaborator, DNS logging sites) or tunnel services (ngrok, Cloudflare quick tunnels). Agents use callbacks to confirm an exploit worked, and tunnels to expose a console or C2. On a server, either is a strong signal; on a workstation it's often a developer.

```kql
let TargetDevice = trim(" ", "{DeviceName}");
let Oast = dynamic(["interact.sh", "oast.fun", "oast.live", "oast.me", "oast.online", "oast.pro", "oast.site",
    "oastify.com", "burpcollaborator.net", "dnslog.cn", "ceye.io"]);
let Webhooks = dynamic(["webhook.site", "requestbin.net", "pipedream.net"]);
let Tunnels = dynamic(["ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net",
    "localhost.run", "loca.lt", "bore.pub"]);
let Servers = DeviceInfo
    | where TimeGenerated > ago(7d)
    | summarize arg_max(TimeGenerated, DeviceType, OSPlatform) by DeviceId
    | where DeviceType == "Server" or OSPlatform startswith "WindowsServer"
    | distinct DeviceId;
union isfuzzy=true
    (DeviceNetworkEvents
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or DeviceName has TargetDevice
        | where RemoteUrl has_any (Oast) or RemoteUrl has_any (Webhooks) or RemoteUrl has_any (Tunnels)
        | extend Category = case(RemoteUrl has_any (Oast), "🛰️ OAST / DNS Log",
                                 RemoteUrl has_any (Tunnels), "🚇 Tunnel", "🪝 Webhook Bin")
        | project TimeGenerated, DeviceId, DeviceName, Category, Destination = RemoteUrl,
                  Process = InitiatingProcessFileName, CommandLine = InitiatingProcessCommandLine,
                  Account = InitiatingProcessAccountName),
    (DeviceProcessEvents
        | where TimeGenerated {TimeRange}
        | where isempty(TargetDevice) or DeviceName has TargetDevice
        | where (FileName in~ ("ngrok", "ngrok.exe"))
            or (FileName in~ ("cloudflared", "cloudflared.exe") and ProcessCommandLine has "tunnel")
        | project TimeGenerated, DeviceId, DeviceName, Category = "🚇 Tunnel", Destination = "(tunnel client)",
                  Process = FileName, CommandLine = ProcessCommandLine, Account = AccountName)
| extend IsServer = DeviceId in (Servers)
| summarize Events = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Destinations = make_set(Destination, 10), CommandLines = make_set(CommandLine, 3)
         by DeviceName, IsServer, Category, Process, Account
| extend SevRank = case(IsServer, 2, Category has "Tunnel", 3, 4)
| extend Severity = case(SevRank == 2, "🟠 High", SevRank == 3, "🟡 Medium", "🔵 Low")
| sort by SevRank asc, LastSeen desc
| project FirstSeen, Severity, Category, DeviceName, IsServer, Process, Account, Events, Destinations, CommandLines, LastSeen
```

---

## 🔧 Enabling Web & WAF Logs

Panels 9, 12, 13 and 17 and the Sensitive Files Served tile stay empty until these logs reach the workspace.

**🌐 IIS logs (panels 12, 13 and 17)**
1. Make sure the web server VM has the Azure Monitor Agent.
2. In Azure Monitor, create a **Data Collection Rule**, add the VM as a resource, and add an **IIS Logs** data source.
3. Send it to your Sentinel workspace. Logs appear in `W3CIISLog` within about 15 minutes.
4. To test in the lab, install IIS on windows-vm: `Install-WindowsFeature Web-Server -IncludeManagementTools` on Windows Server, or `Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole` on Windows client.

**🛡️ Application Gateway WAF logs (panel 9)**
1. You need an Application Gateway on the **WAF_v2** tier with a WAF policy in **Detection** or **Prevention** mode.
2. On the gateway, open **Diagnostic settings** and select **Add diagnostic setting**.
3. Check **ApplicationGatewayFirewallLog** and send it to your Sentinel workspace.
4. With **Azure diagnostics** as the destination table, logs land in `AzureDiagnostics`, which matches panel 9. If you choose **Resource specific**, they land in `AGWFirewallLogs` and panel 9 needs updating.

---

## 🛠️ Tuning Notes

- **Sanctioned processes:** Edit `SanctionedProcs` to match the AI apps your organization approves. Anything not on the list appears as unsanctioned.
- **RemoteUrl coverage:** Defender doesn't always populate `RemoteUrl`, especially on Linux. Turning on network protection improves URL coverage on Windows. Anthropic is also matched by its API IP range (`160.79.104.0/23`); other providers rely on the URL.
- **Pentest hosts:** Approved pentest or red team devices will appear in panels 4 to 6. Exclude them by hostname or device tag.
- **Developers:** Panel 6 at Low severity is visibility, not an alert. Developers installing `openai` or `langchain` is normal.
- **Discovery noise:** Login scripts, inventory tools and admin automation can run discovery commands quickly. Add their parent process to `ExcludedParents` in panel 10 rather than raising `MinDistinct`, so real agent bursts still fire.
- **Corporate IPs:** Add corporate egress IPs and VPN gateways to `Allowlist` in panel 11. Real users' typos and successful sign-ins from a shared IP would otherwise look like a spray that succeeded.
- **Detection rules:** Panels 4, 5 and 7 to 13 aggregate, so they work as scheduled Sentinel analytic rules. Panels 14 to 16 and 18 return one row per event, so they also work as Defender custom detections. Matching rules for panels 4, 12 to 19 and 21 are in the AI Agent & ARTEX Detection Rules README.
- **Burst thresholds:** Each of panels 7 to 9 has its thresholds in `let` statements at the top (`MinPorts`, `MinFailures`, `MinRequests` and so on). Start with the defaults, then raise them if normal traffic shows up.
- **Allowlists:** Add vulnerability scanners, monitoring tools, load balancers and health probes to `Allowlist` in panels 7 to 9, or they'll show as bursts.
- **Blocked inbound connections:** Panel 7 uses `FirewallInboundConnectionBlocked`, which needs Windows Firewall auditing for dropped packets turned on. Without it, the panel only sees accepted connections.
- **Data sources:** Panels 7 and 8 work with Defender data alone. Panel 9 stays empty unless you collect Application Gateway WAF logs. If your WAF uses resource-specific tables, switch panel 9 to `AGWFirewallLogs`.
- **Sensitive path list:** Edit `SensitivePaths` in the overview tiles and panels 12 and 13 to match your stack. Remove paths your apps serve on purpose (for example a real `/backup` route or `/actuator/health`), or they'll show as Served.
- **Internet scanner noise:** Any public site gets constant probes for `/.env` and `/.git/`. Low and Medium rows in panel 12 are background noise; focus on Served, Machine-Speed Sweep and anything that also appears in panel 13.
- **Web servers behind a proxy:** If IIS sits behind Application Gateway or a load balancer, `cIP` is the proxy's address, not the client's. Log the `X-Forwarded-For` header as a custom IIS field and use it instead, or panel 18 won't match sign-in IPs.
- **Honeytoken decoy:** Serve a fake `/.env` containing honeytoken credentials. A probe in panel 12 followed by a honeytoken sign-in in panel 13 is a confirmed attacker, and it triggers the Honeytoken Isolation playbook.
- **MCP configs:** AI apps rewrite their own config when users add servers through the app, so those rows rank Low. A config written by a shell or script is the one to investigate. Open the file and check every server's `command` and `args`.
- **Key harvesting:** Developers set API keys in environment variables all the time, so panel 15 only matches key names when a search tool runs, not when a key is exported. Add approved secret-scanning pipelines to `ExcludedAccounts`.
- **Offensive containers:** Pentest and red team hosts will show here. Exclude them by hostname or device tag. The image lists are regex patterns, so add new tool names as they appear.
- **ARTEX indicators:** Panel 17 uses indicators from the [ThreatDefence ARTEX detections](https://github.com/ThreatDefence/artex-detections) project. They change as ARTEX and its forks change, so refresh the lists from that project now and then. Medium-confidence user agents (norma, HexStrike) are shared with other agent tools and rank Medium.
- **Web and database shells:** Java apps such as Jenkins start shells as part of normal work, so Java parents rank Medium. Add known-good command fragments to `ExcludedCmds`.
- **App abuse:** Panel 19 needs Entra audit logs and service principal sign-in logs in the workspace. Users adding app credentials rank Low; they're normal admin work, but useful context during an investigation.
- **Password rhythm:** Panel 20 scores each IP per hour. A low `Rhythm` with many users is a script; a high one is usually users mistyping passwords behind a shared NAT.
- **Callbacks:** Panel 21 marks servers using `DeviceInfo`. On Linux without network protection, `RemoteUrl` is often empty, so only the tunnel-process half catches Linux hosts.
