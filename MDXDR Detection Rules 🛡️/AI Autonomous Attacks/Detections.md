# 🚨 AI Agent & ARTEX Detection Rules

Thirteen detection rules for autonomous AI attack agents like ARTEX, its forks (ScopeWeaver, AntiFox, Guanlan SEC and others) and the steps their operators take. Six run as Microsoft Sentinel scheduled analytic rules and seven as Defender custom detections. They pair with the **AI & Autonomous Threats** workbook.

| # | Rule | Platform | Severity | Catches |
|---|------|----------|----------|---------|
| 1 | 🤖 LLM-Driven Offensive Agent | Sentinel | High / Medium | A host making unsanctioned LLM API calls and running offensive tools |
| 2 | 🔗 Recon to Sign-In | Sentinel | High / Medium | An IP that probed sensitive web paths, then signed in to Entra ID |
| 3 | 🔓 Sensitive File Served | Sentinel | High | A web server returning `.env`, `.git`, keys or configs with a 2xx |
| 4 | 🎯 ARTEX Indicator Hit | Sentinel | High | ARTEX user agents, probe markers, host artifacts, hashes and toolkit domains |
| 5 | 👑 App Granted Itself Access | Sentinel | High | An app assigning itself a role or adding its own credential |
| 6 | 🗝️ Service Principal Secret Guessed | Sentinel | High | Repeated bad client secrets, then a successful sign-in from the same IP |
| 7 | 🔌 MCP Config Written by a Script | Defender | Medium | An AI app's MCP config changed by a shell or script |
| 8 | 🔑 LLM API Key Harvesting | Defender | High | Searches for LLM API keys, `.env` sweeps, or AI credential files read or copied |
| 9 | 🐳 Offensive AI or C2 Container | Defender | High | Docker pulling or running an offensive AI agent or C2 framework |
| 10 | 🐚 Web or Database Service Spawned a Shell | Defender | High | IIS, Apache, nginx, Tomcat or SQL Server starting a shell or download tool |
| 11 | 📞 Server Callback to OAST or Tunnel Service | Defender | Medium | A server reaching interactsh, webhook bins, DNS loggers, ngrok or Cloudflare tunnels |
| 12 | 🖥️ ARTEX Console Listening | Defender | High | A process listening on ARTEX console ports, or the backdoored console binary |
| 13 | 📦 ARTEX Install or Setup | Defender | High | Cloning, installing or bringing up ARTEX or a renamed fork |

---

## ☁️ Sentinel Scheduled Rules

## 1. 🤖 LLM-Driven Offensive Agent

The main signature of an autonomous attack tool like ARTEX running on one of your hosts: a non-browser process calls an LLM API, and the same host runs offensive tooling.

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

**🛠️ Tuning**
- Add approved pentest hosts to `ExcludedDevices`.
- Add your sanctioned AI apps to `SanctionedProcs`.
- On Linux, `RemoteUrl` is often empty, so only Anthropic's IP range (`160.79.104.0/23`) matches. Add other providers' IP ranges if you need them on Linux.
- Two tools trigger Medium; three or more trigger High.

---

## 2. 🔗 Recon to Sign-In

An IP that requested sensitive web paths in the last 24 hours, then signed in (or tried to) to Entra ID. This is the harvest-then-log-in chain: an agent finds credentials in an exposed file and uses them.

```kql
let ProbeWindow = 1d;
let Allowlist = dynamic([]);   // corporate egress IPs, approved scanners
let ValidPwCodes = dynamic(["50072", "50074", "50076", "50079", "50158", "53003"]);
let SensitivePaths = @"(?i)(/\.env|/\.git(/|$)|/\.aws/|/\.ssh/|/\.svn/|/\.hg/|/\.ds_store|/\.htpasswd|/\.htaccess|/\.npmrc|/\.dockercfg|/\.docker/|/\.vscode/|/\.idea/|/\.kube/|wp-config\.php|/config\.(php|json|ya?ml|ini)|/web\.config|/appsettings(\.\w+)?\.json|/phpinfo|/server-status|/actuator|/docker-compose\.ya?ml|id_rsa|\.(sql|bak|old|backup|swp|tar|tgz|zip)$|/backup)";
let Probers = W3CIISLog
    | where TimeGenerated > ago(ProbeWindow)
    | where isnotempty(cIP) and cIP !in (Allowlist)
    | where csUriStem matches regex SensitivePaths
    | summarize FirstProbe = min(TimeGenerated),
                ProbedPaths = dcount(csUriStem),
                Served = countif(tostring(scStatus) startswith "2"),
                SamplePaths = make_set(csUriStem, 15),
                WebServer = take_any(Computer)
             by IPAddress = cIP;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(ProbeWindow)
| where ingestion_time() > ago(1h)
| where IPAddress in ((Probers | project IPAddress))
| lookup kind=inner (Probers | project IPAddress, FirstProbe) on IPAddress
| where TimeGenerated >= FirstProbe
| summarize SignIns = count(),
            Successes = countif(ResultType == "0"),
            ValidPw = countif(ResultType in (ValidPwCodes)),
            Users = make_set(UserPrincipalName, 20),
            SuccessUsers = make_set_if(UserPrincipalName, ResultType == "0", 10),
            Account = take_any(UserPrincipalName),
            Apps = make_set(AppDisplayName, 10),
            FirstSignIn = min(TimeGenerated),
            LastSignIn = max(TimeGenerated)
         by IPAddress
| lookup kind=inner Probers on IPAddress
| extend Account = iff(array_length(SuccessUsers) > 0, tostring(SuccessUsers[0]), Account)
| extend MinutesToSignIn = datetime_diff("minute", FirstSignIn, FirstProbe)
| extend Outcome = case(
    Successes > 0, "Successful sign-in",
    ValidPw > 0, "Valid password",
    "Failed sign-in")
| extend Severity = iff(Successes > 0 or ValidPw > 0, "High", "Medium")
| project FirstProbe, Severity, Outcome, IPAddress, Account, MinutesToSignIn, Served, ProbedPaths,
          SamplePaths, WebServer, SignIns, Successes, SuccessUsers, ValidPw, Users, Apps,
          FirstSignIn, LastSignIn
```

| Setting | Value |
|---------|-------|
| 📛 Name | AI - Recon to Sign-In |
| 🔴 Severity | High (overridden by the `Severity` column) |
| ⏱️ Run every / Lookup data from | 1 hour / 1 day |
| 🎯 Alert threshold | Number of results > 0 |
| 🧾 Event grouping | Trigger an alert for each event |
| 🧩 Entities | IP: `Address` = `IPAddress` · Account: `FullName` = `Account` · Host: `HostName` = `WebServer` |
| 📋 Custom details | `Outcome`, `SamplePaths`, `Served`, `MinutesToSignIn`, `Users`, `Apps` |
| 🏷️ Alert name format | `Recon to sign-in from {{IPAddress}}: {{Outcome}}` |
| 🎚️ Severity column | `Severity` |
| 🗂️ Alert grouping | Group into one incident when **IP** matches, within 24 hours |

**🛠️ Tuning**
- Add corporate egress IPs, VPN gateways and approved scanners to `Allowlist`. Otherwise a scanner and a real user behind the same NAT look like this attack.
- If IIS sits behind Application Gateway or a load balancer, `cIP` is the proxy's address. Log `X-Forwarded-For` as a custom IIS field and use it instead of `cIP`.
- **🍯 Honeytoken pairing:** serve a decoy `/.env` containing honeytoken credentials. A successful or valid-password row for the honeytoken account is a confirmed attacker. Add an automation rule that runs the Honeytoken Isolation playbook when the account is a honeytoken.

---

## 3. 🔓 Sensitive File Served

A web server returned a sensitive file with a 2xx response. Treat every alert as a possible secret exposure.

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

**🛠️ Tuning**
- The path list is narrower than panel 17 on purpose. It leaves out paths that are often legitimate (`/backup` routes, `/actuator/health`, generic `config.json`).
- If an app serves one of these paths on purpose, fix it rather than excluding it. Configs and keys shouldn't be in a web root.

**📋 Response:** confirm the file contents, rotate every credential in it, remove the file from the web root, and check Recon to Sign-In for the same source IP.

---

## 4. 🎯 ARTEX Indicator Hit

Any high-confidence ARTEX marker in web, sign-in or endpoint data. Each of these names ARTEX or is unique to its operators, so one hit is enough to alert. Generic agent user agents (norma, HexStrike) are left out of the rule and shown in panel 22 instead.

```kql
let UAs = @"(?i)artex|scopeweaver|spa-api-recon";
let WebMarkers = @"(?i)zzz-nonexistent-xyz123|zzz_nonexistent_abc\.txt|notexist-xyz|artex[_-]?probe|artex_write_probe|artx_persist_ok|artex_control_marker_zz9q|%artex_probe_unset%|callback\?code=aaaa&state=notvalidb64";
let HostPaths = @"(?i)artex-probe-|\\programdata\\artx5v\\|zzartx0000\.php|[\\/](cl1217|f1219a|z1219)\.jsp$|graphics-hook-filter64\.dll|graphics-hook_config\.bin";
let CmdMarkers = @"(?i)artex-probe-|artexprobe|\\programdata\\artx5v|art18-|artex_write_probe|artx_persist_ok|artex_control_marker_zz9q|tomicdd/artex|congdonglinux/artex|microsoftedgeupdatetaskmachine(ua|core)\{(cec15d9b|4c33ce3f)";
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
        | where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
        | extend Request = strcat(csUriStem, "?", csUriQuery)
        | where csUserAgent matches regex UAs or Request matches regex WebMarkers
        | project TimeGenerated, Source = "IIS", IPAddress = cIP, HostName = Computer, Account = "",
                  Detail = iff(Request matches regex WebMarkers, Request, csUserAgent)),
    (AzureDiagnostics
        | where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
        | where Category == "ApplicationGatewayAccessLog"
        | where userAgent_s matches regex UAs or requestUri_s matches regex WebMarkers
        | project TimeGenerated, Source = "App Gateway", IPAddress = clientIP_s, HostName = host_s, Account = "",
                  Detail = iff(requestUri_s matches regex WebMarkers, requestUri_s, userAgent_s)),
    (union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
        | where UserAgent matches regex UAs
        | project TimeGenerated, Source = "Entra sign-in", IPAddress, HostName = "", Account = UserPrincipalName,
                  Detail = UserAgent),
    (DeviceFileEvents
        | where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
        | where FolderPath matches regex HostPaths or SHA256 in (Hashes)
        | project TimeGenerated, Source = "File", IPAddress = "", HostName = DeviceName,
                  Account = InitiatingProcessAccountName, Detail = FolderPath),
    (DeviceProcessEvents
        | where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
        | where ProcessCommandLine matches regex CmdMarkers or SHA256 in (Hashes) or FolderPath endswith "/app/artex"
        | project TimeGenerated, Source = "Process", IPAddress = "", HostName = DeviceName,
                  Account = AccountName, Detail = ProcessCommandLine),
    (DeviceNetworkEvents
        | where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
        | where RemoteUrl has_any (Domains)
        | project TimeGenerated, Source = "Network", IPAddress = RemoteIP, HostName = DeviceName,
                  Account = InitiatingProcessAccountName, Detail = RemoteUrl)
| summarize Hits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Samples = make_set(Detail, 5)
         by Source, IPAddress, HostName, Account
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - Indicator Hit |
| 🔴 Severity | High |
| ⏱️ Run every / Lookup data from | 1 hour / 2 hours |
| 🎯 Alert threshold | Number of results > 0 |
| 🧩 Entities | IP: `IPAddress` · Host: `HostName` · Account: `Account` |
| 📋 Custom details | `Source`, `Samples`, `Hits` |
| 🏷️ Alert name format | `ARTEX indicator in {{Source}}` |
| 🗂️ Alert grouping | Group into one incident when **IP** or **Host** matches, within 24 hours |

**🛠️ Tuning**

- The `X-ARTX-KEY` request header is a known marker, but IIS doesn't log request headers by default. Add it as a custom IIS log field if you want it covered.
- Indicators change. Check the ThreatDefence project for new user agents and markers, or import its `sentinel-watchlist.csv` as a watchlist and sweep it in hunts.
- The project's IP addresses are left out on purpose: cloud and VPS addresses get reassigned, so they suit hunting, not alerting.

---

## 5. 👑 App Granted Itself Access

An app or service principal assigned itself a role or added a credential to itself. A legitimate app almost never changes its own access, but an attacker who controls an app uses this to escalate or keep access.

```kql
let RoleOps = dynamic(["Add app role assignment to service principal", "Add member to role", "Add eligible member to role"]);
AuditLogs
| where TimeGenerated > ago(2h) and ingestion_time() > ago(1h)
| where OperationName in (RoleOps)
    or OperationName has "Certificates and secrets management"
    or OperationName == "Add service principal credentials"
| extend InitiatorSpId = tostring(InitiatedBy.app.servicePrincipalId),
         InitiatorApp = tostring(InitiatedBy.app.displayName),
         TargetName = tostring(TargetResources[0].displayName)
| where isnotempty(InitiatorSpId)
| where tostring(TargetResources) has InitiatorSpId or TargetName == InitiatorApp
| extend Action = iff(OperationName in (RoleOps), "Assigned itself a role", "Added its own credential")
| project TimeGenerated, Action, InitiatorApp, InitiatorSpId, OperationName, TargetName,
          Result, CorrelationId, TargetResources
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - App Granted Itself Access |
| 🔴 Severity | High |
| ⏱️ Run every / Lookup data from | 1 hour / 2 hours |
| 🎯 Alert threshold | Number of results > 0 |
| 🧩 Entities | Cloud application: `Name` = `InitiatorApp` |
| 📋 Custom details | `Action`, `OperationName`, `TargetName` |
| 🏷️ Alert name format | `App {{InitiatorApp}} {{Action}}` |

**🛠️ Tuning**

- A few automation tools rotate their own secrets on a schedule. If one shows up and is expected, exclude it by `InitiatorSpId`.

**📋 Response:** remove the new role or credential, then review the app's other credentials, owners and recent sign-ins (panel 24). If it's compromised, disable the service principal.

---

## 6. 🗝️ Service Principal Secret Guessed

Five or more invalid client secrets for a service principal, then a successful sign-in from the same IP address. That's someone guessing or testing stolen secrets until one works.

```kql
let MinFailures = 5;
let SecretFailCodes = dynamic(["7000215", "7000222"]);   // invalid / expired client secret
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(2h)
| summarize Failures = countif(ResultType in (SecretFailCodes)),
            Successes = countif(ResultType == "0"),
            FirstFailure = minif(TimeGenerated, ResultType in (SecretFailCodes)),
            LastSuccess = maxif(TimeGenerated, ResultType == "0"),
            Resources = make_set(ResourceDisplayName, 10)
         by ServicePrincipalName, ServicePrincipalId, AppId, IPAddress
| where Failures >= MinFailures and Successes > 0
| where LastSuccess > FirstFailure and LastSuccess > ago(1h)
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - Service Principal Secret Guessed |
| 🔴 Severity | High |
| ⏱️ Run every / Lookup data from | 1 hour / 2 hours |
| 🎯 Alert threshold | Number of results > 0 |
| 🧩 Entities | IP: `Address` = `IPAddress` · Cloud application: `AppId` = `AppId` |
| 📋 Custom details | `Failures`, `Successes`, `Resources` |
| 🏷️ Alert name format | `Secret guessed for {{ServicePrincipalName}} from {{IPAddress}}` |

**🛠️ Tuning**

- After a secret rotation, a misconfigured app may fail with the old secret before picking up the new one. That shows as failures then success from your own IPs, so add known app hosts to an allowlist.
- Needs the **Service principal sign-in logs** category enabled in Entra diagnostic settings.

**📋 Response:** rotate the app's secrets, review what it accessed after the success, and block the source IP.

---

## 🛡️ Defender Custom Detections

Rules 7 to 13 return one row per event, so they run as Defender custom detections: they alert faster than scheduled rules and can act on the device.

---

## 7. 🔌 MCP Config Written by a Script

From panel 19. An MCP config for Claude, Cursor, VS Code or Windsurf was created or changed by a shell, script or unknown process instead of the AI app or editor. That's how a malicious MCP server gets planted for persistence.

```kql
let McpFiles = dynamic(["claude_desktop_config.json", "mcp.json", ".mcp.json", "mcp_config.json"]);
let McpFolders = @"(?i)[\\/](Claude|\.claude|\.cursor|\.vscode|Code|windsurf|\.codeium)[\\/]";
let AppProcs = dynamic([
    "claude.exe", "claude", "cursor.exe", "cursor", "code.exe", "code", "windsurf.exe", "windsurf",
    "explorer.exe", "notepad.exe", "notepad++.exe", "vim", "nano", "gedit"]);
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName =~ ".mcp.json"
    or (FileName in~ (McpFiles) and FolderPath matches regex McpFolders)
| where InitiatingProcessFileName !in~ (AppProcs)
| project Timestamp, DeviceId, DeviceName, ReportId, ActionType, FolderPath, SHA256,
          InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

| Setting | Value |
|---------|-------|
| 📛 Name | AI - MCP Config Written by Script |
| 🟡 Severity | Medium |
| 🏷️ Category | Persistence |
| ⏱️ Frequency | Continuous (NRT) |
| 🧩 Impacted entities | Device: `DeviceId` · User: `InitiatingProcessAccountUpn` |
| ⚙️ Actions | None. Investigate first; a malicious config needs the server removed, not the device isolated |

**📋 Response:** open the config and check every server's `command`, `args` and `env`. Look for unknown binaries, scripts in temp folders, `npx` or `uvx` packages you don't recognize, and remote URLs.

---

## 8. 🔑 LLM API Key Harvesting

From panel 20. Searching for LLM API keys, sweeping a disk for `.env` files, or reading, copying or uploading Claude, Codex or Copilot credential files.

```kql
let KeyPrefixes = @"sk-(ant|proj|or)-";
let KeyNames = dynamic([
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY", "GROQ_API_KEY",
    "MISTRAL_API_KEY", "COHERE_API_KEY"]);
let SearchTools = dynamic(["grep", "egrep", "rg", "ag", "ack", "findstr.exe", "strings", "awk"]);
let AiCredFiles = @"(?i)\.claude[\\/]\.credentials\.json|\.codex[\\/]auth\.json|github-copilot[\\/](hosts|apps)\.json";
let ReadTools = dynamic(["cat", "cp", "scp", "tar", "zip", "base64", "curl", "wget", "xxd",
    "type", "copy", "xcopy", "robocopy", "certutil.exe", "powershell.exe", "pwsh.exe", "pwsh"]);
let ExcludedAccounts = dynamic([]);   // approved secret-scanning service accounts
DeviceProcessEvents
| where Timestamp > ago(1h)
| where AccountName !in~ (ExcludedAccounts)
| extend Cmd = ProcessCommandLine, Proc = tolower(FileName)
| extend HasKey = Cmd has_any (KeyNames) or Cmd matches regex KeyPrefixes
| extend Pattern = case(
    Proc in~ (ReadTools) and Cmd matches regex AiCredFiles, "AI credential file access",
    Proc in~ (SearchTools) and HasKey, "Key search",
    Proc in~ ("powershell.exe", "pwsh.exe", "pwsh") and Cmd has "Select-String" and HasKey, "Key search",
    Proc in~ ("find", "fd") and Cmd matches regex @"-name\s+['""]?\*?\.env\b", "Env file sweep",
    Cmd has_any ("Get-ChildItem", "gci") and Cmd has "Recurse" and Cmd contains ".env", "Env file sweep",
    "")
| where isnotempty(Pattern)
| project Timestamp, DeviceId, DeviceName, ReportId, Pattern, AccountName, AccountUpn = InitiatingProcessAccountUpn,
          FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

| Setting | Value |
|---------|-------|
| 📛 Name | AI - LLM API Key Harvesting |
| 🔴 Severity | High |
| 🏷️ Category | Credential access |
| ⏱️ Frequency | Every hour (the query uses `extend` and `case`, which near-real-time rules may not support) |
| 🧩 Impacted entities | Device: `DeviceId` · User: `AccountUpn` |
| ⚙️ Actions | Optional: collect investigation package |

**📋 Response:** rotate every LLM API key and AI tool login on the device, check the provider's usage dashboard for spend or requests you don't recognize, and look for outbound connections from the same process.

> Secret scanners (trufflehog, gitleaks) are left out of this rule because security teams run them routinely. They still show in panel 20.

---

## 9. 🐳 Offensive AI or C2 Container

From panel 21. Docker or Podman pulling or running an offensive AI agent (ARTEX, ScopeWeaver and similar) or a C2 framework (Sliver, Empire, Mythic, Havoc, Covenant, Metasploit).

```kql
let ContainerCli = dynamic(["docker", "docker.exe", "podman", "podman.exe", "nerdctl", "docker-compose", "docker-compose.exe"]);
let OffensiveImages = @"(?i)artex|scopeweaver|scopesentry|pentestgpt|hexstrike|sliver|bcsecurity|mythic|havoc|covenant|metasploit";
let ExcludedDevices = dynamic([]);   // approved pentest / red team hosts
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ (ContainerCli)
| where ProcessCommandLine has_any ("pull", "run", "create", "compose", "up", "build")
| where ProcessCommandLine matches regex OffensiveImages
| where DeviceName !in~ (ExcludedDevices)
| project Timestamp, DeviceId, DeviceName, ReportId, AccountName, AccountUpn = InitiatingProcessAccountUpn,
          ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```

| Setting | Value |
|---------|-------|
| 📛 Name | AI - Offensive AI or C2 Container |
| 🔴 Severity | High |
| 🏷️ Category | Execution |
| ⏱️ Frequency | Continuous (NRT) |
| 🧩 Impacted entities | Device: `DeviceId` · User: `AccountUpn` |
| ⚙️ Actions | Optional: isolate device, once you've excluded approved pentest hosts |

> Recon toolkits (Kali, ProjectDiscovery images) are left out of the rule because admins and developers use them too. They still show in panel 21, and panel 21 ranks any of these Critical when the same host also makes unsanctioned LLM calls.

---

## 10. 🐚 Web or Database Service Spawned a Shell

A web server or database started a shell, script host, or download and recon tool. That usually means a web shell, an injection or `xp_cmdshell`: the point where an attack on an application becomes code running on the server.

```kql
let WebParents = dynamic(["w3wp.exe", "iisexpress.exe", "httpd.exe", "httpd", "apache2", "nginx.exe", "nginx",
    "php-cgi.exe", "php-fpm", "tomcat.exe", "tomcat9.exe"]);
let DbParents = dynamic(["sqlservr.exe", "mysqld.exe", "mysqld", "postgres.exe", "postgres", "oracle.exe", "mongod.exe", "mongod"]);
let Children = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "wscript.exe", "cscript.exe", "mshta.exe",
    "bash", "sh", "dash", "zsh", "certutil.exe", "bitsadmin.exe", "curl.exe", "curl", "wget", "whoami.exe", "whoami",
    "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe", "tasklist.exe", "schtasks.exe", "rundll32.exe",
    "regsvr32.exe", "nc", "ncat", "netcat", "python", "python3", "perl"]);
let ExcludedCmds = dynamic([]);   // known-good command fragments, e.g. a monitoring script
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in~ (WebParents) or InitiatingProcessFileName in~ (DbParents)
| where FileName in~ (Children)
| where not(ProcessCommandLine has_any (ExcludedCmds))
| project Timestamp, DeviceId, DeviceName, ReportId, AccountName, AccountUpn = InitiatingProcessAccountUpn,
          InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - Web or Database Service Spawned a Shell |
| 🔴 Severity | High |
| 🏷️ Category | Execution |
| ⏱️ Frequency | Continuous (NRT), or every hour if NRT isn't accepted |
| 🧩 Impacted entities | Device: `DeviceId` · User: `AccountUpn` |
| ⚙️ Actions | Optional: isolate device, once known-good admin scripts are excluded |

**🛠️ Tuning**

- Java is left out of the rule (it's in panel 23) because Java apps like Jenkins start shells as part of normal work. Add `java.exe` back for servers that only run a web app.
- Some PHP apps call `sh` to send mail. Add those command fragments to `ExcludedCmds`.

**📋 Response:** look at the command line and parent. Check the web root for recently written files (a web shell), and the SQL Server for `xp_cmdshell` being enabled.

---

## 11. 📞 Server Callback to OAST or Tunnel Service

A server reached an out-of-band testing service (interactsh, Burp Collaborator, DNS loggers, webhook bins) or ran a tunnel client (ngrok, Cloudflare quick tunnels). Agents use callbacks to confirm an exploit worked, and tunnels to expose a console or C2.

```kql
let Destinations = dynamic(["interact.sh", "oast.fun", "oast.live", "oast.me", "oast.online", "oast.pro", "oast.site",
    "oastify.com", "burpcollaborator.net", "dnslog.cn", "ceye.io", "webhook.site", "requestbin.net", "pipedream.net",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "localhost.run", "loca.lt", "bore.pub"]);
let Servers = DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, DeviceType, OSPlatform) by DeviceId
    | where DeviceType == "Server" or OSPlatform startswith "WindowsServer"
    | distinct DeviceId;
union
    (DeviceNetworkEvents
        | where Timestamp > ago(1h)
        | where RemoteUrl has_any (Destinations)
        | project Timestamp, DeviceId, DeviceName, ReportId, Destination = RemoteUrl,
                  Process = InitiatingProcessFileName, CommandLine = InitiatingProcessCommandLine,
                  AccountUpn = InitiatingProcessAccountUpn),
    (DeviceProcessEvents
        | where Timestamp > ago(1h)
        | where FileName in~ ("ngrok", "ngrok.exe")
            or (FileName in~ ("cloudflared", "cloudflared.exe") and ProcessCommandLine has "tunnel")
        | project Timestamp, DeviceId, DeviceName, ReportId, Destination = "(tunnel client)",
                  Process = FileName, CommandLine = ProcessCommandLine, AccountUpn = InitiatingProcessAccountUpn)
| where DeviceId in (Servers)
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - Server Callback to OAST or Tunnel Service |
| 🟡 Severity | Medium |
| 🏷️ Category | Command and control |
| ⏱️ Frequency | Every hour |
| 🧩 Impacted entities | Device: `DeviceId` · User: `AccountUpn` |
| ⚙️ Actions | None until tuned |

**🛠️ Tuning**

- Servers only. Developers use these services from workstations, so workstation hits stay in panel 26.
- If your organization uses Cloudflare Tunnel on purpose, the rule only catches quick tunnels and `cloudflared tunnel` launches. Exclude your managed tunnel servers by name.
- On Linux without network protection, `RemoteUrl` is often empty, so the network half may miss Linux servers. The tunnel-process half still works.

---

## 12. 🖥️ ARTEX Console Listening

A process listening on an ARTEX console port (8787, 8788, 8790 or 8890), or the console binary from the backdoored ARTEX container images. Someone running ARTEX inside your network is an authorized tester, an insider or an intruder. This replaces the older GUI listener query, which only checked 8787 and 8788.

```kql
let ConsolePorts = dynamic([8787, 8788, 8790, 8890]);
let KnownListeners = dynamic(["rserver", "rstudio-server", "rsession"]);   // RStudio Server also uses 8787
union
    (DeviceNetworkEvents
        | where Timestamp > ago(1h)
        | where ActionType == "ListeningConnectionCreated"
        | where LocalPort in (ConsolePorts)
        | where InitiatingProcessFileName !in~ (KnownListeners)
        | project Timestamp, DeviceId, DeviceName, ReportId, Signal = strcat("Listening on ", LocalPort),
                  Process = InitiatingProcessFileName, Path = InitiatingProcessFolderPath,
                  CommandLine = InitiatingProcessCommandLine, AccountUpn = InitiatingProcessAccountUpn),
    (DeviceProcessEvents
        | where Timestamp > ago(1h)
        | where FolderPath endswith "/app/artex"
            or (InitiatingProcessFolderPath endswith "/app/artex" and FileName in~ ("sh", "bash"))
        | project Timestamp, DeviceId, DeviceName, ReportId, Signal = "ARTEX console binary",
                  Process = FileName, Path = FolderPath, CommandLine = ProcessCommandLine,
                  AccountUpn = InitiatingProcessAccountUpn)
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - Console Listening |
| 🔴 Severity | High |
| 🏷️ Category | Execution |
| ⏱️ Frequency | Every hour |
| 🧩 Impacted entities | Device: `DeviceId` · User: `AccountUpn` |
| ⚙️ Actions | Optional: isolate device, outside approved pentest hosts |

**🛠️ Tuning**

- Other dev tools can use these ports. Add them to `KnownListeners` by process name, or exclude approved pentest hosts by device group.
- A console listening on all interfaces (not just `127.0.0.1`) is worse: it can be reached remotely. Check `LocalIP` in the raw event.

---

## 13. 📦 ARTEX Install or Setup

Cloning the ARTEX repo (or a fork), running its install script, or bringing up its containers with Docker Compose. Catches the tool being set up, before it runs.

```kql
let Names = @"(?i)artex|scopeweaver|scopesentry";
DeviceProcessEvents
| where Timestamp > ago(1h)
| where (FileName in~ ("git", "git.exe") and ProcessCommandLine has "clone" and ProcessCommandLine matches regex Names)
    or (ProcessCommandLine has_any ("install.sh", "setup.sh")
        and (ProcessCommandLine matches regex Names or InitiatingProcessFolderPath matches regex Names or FolderPath matches regex Names))
    or (FileName has "docker" and ProcessCommandLine has "compose" and ProcessCommandLine has_any ("up", "build", "start")
        and (ProcessCommandLine matches regex Names or InitiatingProcessFolderPath matches regex Names or FolderPath matches regex Names))
| extend Signal = case(
    ProcessCommandLine has "clone", "Repo clone",
    ProcessCommandLine has_any ("install.sh", "setup.sh"), "Install script",
    "Container bring-up")
| project Timestamp, DeviceId, DeviceName, ReportId, Signal, AccountName, AccountUpn = InitiatingProcessAccountUpn,
          FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

| Setting | Value |
|---------|-------|
| 📛 Name | ARTEX - Install or Setup |
| 🔴 Severity | High |
| 🏷️ Category | Execution |
| ⏱️ Frequency | Continuous (NRT), or every hour if NRT isn't accepted |
| 🧩 Impacted entities | Device: `DeviceId` · User: `AccountUpn` |
| ⚙️ Actions | Optional: isolate device, outside approved pentest hosts |

**🛠️ Tuning**

- Matches on the name, so a renamed fork in a folder called something else won't hit. Rules 1, 9 and 12 catch ARTEX by behavior instead.
- Exclude approved pentest hosts by device group.

**📋 Response:** confirm whether the install was authorized. If not, isolate the device, check who ran it, and look for LLM API keys configured on the host (rule 8).

---

## 🛠️ Creating the Rules

**Sentinel rules (1 to 6):** go to **Microsoft Sentinel > Analytics > Create > Scheduled query rule** (in the Defender portal: **Microsoft Sentinel > Configuration > Analytics**). Enter the name and severity from the rule's settings, paste the query, map entities, add custom details, the alert name format and (for rules 1 and 2) the severity column, set the schedule and threshold, turn on incident creation and alert grouping, then **Review + create**.

**Defender custom detections (7 to 13):** in the Defender portal, go to **Hunting > Advanced hunting**, run the query, and select **Create detection rule**. Enter the name, severity, category and frequency, map the impacted entities, add any actions, set the scope (exclude pentest device groups), then **Submit**. If Defender won't accept **Continuous (NRT)** for a query, choose **Every hour**.

---

## 🧪 Lab Testing

| Rule | How to trigger it in the lab |
|------|------------------------------|
| 🤖 1 | On Kali: `curl -s https://api.anthropic.com/v1/models -o /dev/null`, then run three of the fake tool binaries (`nuclei`, `httpx`, `ffuf`) within the same hour. |
| 🔗 2 | Request `http://<windows-vm public IP>/.env` from Kali, then sign in to the Microsoft 365 portal from Kali with a test account (wrong password is fine). Kali must reach the site by its **public** IP, so the source in IIS matches the IP Entra sees. |
| 🔓 3 | Create `C:\inetpub\wwwroot\appsettings.json` with dummy content and request it. IIS doesn't serve unknown extensions like `.env` by default, which is one reason to test with `.json`. |
| 🎯 4 | From Kali: `curl -A "artex-verify/1.0" http://<windows-vm public IP>/zzz-nonexistent-xyz123`. Both the user agent and the path match. A 404 is fine. |
| 👑 5 | Use your Power BI app registration: sign in as the app with Microsoft Graph PowerShell and have it add a new secret to itself (needs `Application.ReadWrite.OwnedBy`, and the app listed as its own owner). Delete the secret afterwards. |
| 🗝️ 6 | Request a token for a test app with a wrong client secret 5 times, then the right one, from the same machine. |
| 🔌 7 | On Kali: `mkdir -p ~/.cursor && echo '{"mcpServers":{}}' > ~/.cursor/mcp.json`. The file is written by `bash`, not an editor. |
| 🔑 8 | On Kali: `grep -r "ANTHROPIC_API_KEY" ~ 2>/dev/null` and `find / -name "*.env" 2>/dev/null`. Neither needs a real key. |
| 🐳 9 | On Kali with Docker installed: `docker pull sliver-test:latest`. The image doesn't exist, so the pull fails, but the command line is still logged. |
| 🐚 10 | On windows-vm with IIS: create an `.aspx` test page that runs `cmd.exe /c whoami`, then request it. Or in SQL Server, enable `xp_cmdshell` and run `EXEC xp_cmdshell 'whoami'`. Remove both afterwards. |
| 📞 11 | Run `curl https://webhook.site/<any-id>`. The rule only fires on servers, so on your Windows 11 VM or Kali the hit shows in panel 26 but not as an alert. To test the alert, use a Windows Server VM or add the device to the `Servers` list. |
| 🖥️ 12 | On Kali: `python3 -m http.server 8790`, then stop it. |
| 📦 13 | On Kali: `mkdir -p /tmp/artex-test && echo 'echo hi' > /tmp/artex-test/install.sh && bash /tmp/artex-test/install.sh`. The command line names an `artex` folder and `install.sh`, so it matches without installing anything. Delete the folder afterwards. |

Events take up to about 15 minutes to arrive. Run each query by hand first, then wait for the next scheduled run.
