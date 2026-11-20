# 🚨 AI & Autonomous Threats: Detection Rules

Three Microsoft Sentinel scheduled analytic rules built from the AI & Autonomous Threats 1.5 workbook. They cover gaps that Defender, Entra ID Protection and the WAF don't alert on out of the box.

| # | Rule | From panel | Severity | Catches |
|---|------|------------|----------|---------|
| 1 | 🤖 LLM-Driven Offensive Agent | 6 | High | A host making unsanctioned LLM API calls **and** running offensive tools |
| 2 | 🔗 Recon to Sign-In | 18 | High / Medium | An IP that probed sensitive web paths, then tried to sign in to Entra ID |
| 3 | 🔓 Sensitive File Served | 17 | High | A web server returning `/.env`, `/.git/`, keys or configs with a 2xx |

> 🧪 Run each query in **Logs** first and test it with the lab steps below before you enable the rule.

---

## 🧭 How These Rules Avoid Duplicate Alerts

Each rule runs every hour but looks back further, so it can correlate activity across a longer window or catch logs that arrive late. To stop the same activity alerting every hour, each query only returns a result when **new** data arrived in the last hour:

- Rules 2 and 3 filter on `ingestion_time() > ago(1h)`. This also catches events that were ingested late, which a plain `TimeGenerated` filter would miss.
- Rule 1 requires the latest LLM call or tool run to be in the last hour. Ongoing activity alerts again, and alert grouping folds those alerts into the same incident.

---

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

## 🛠️ Creating the Rules in Sentinel

1. Go to **Microsoft Sentinel > Analytics > Create > Scheduled query rule**. In the Defender portal: **Microsoft Sentinel > Configuration > Analytics**.
2. **General:** enter the name and severity from the rule's table.
3. **Set rule logic:** paste the query. Map entities, add custom details, and set the alert name format and severity column under **Alert details**. Set the schedule and threshold.
4. **Incident settings:** keep incident creation on and set alert grouping from the table.
5. **Automated response:** attach automation rules if you want (for example the Honeytoken Isolation playbook on Rule 2).
6. **Review + create.**

---

## 🧪 Lab Testing

| Rule | How to trigger it in the lab |
|------|------------------------------|
| 🤖 1 | On Kali: `curl -s https://api.anthropic.com/v1/models -o /dev/null`, then run three of the fake tool binaries (`nuclei`, `httpx`, `ffuf`) within the same hour. |
| 🔗 2 | Request `http://<windows-vm public IP>/.env` from Kali, then sign in to the Microsoft 365 portal from Kali with a test account (wrong password is fine). Kali must reach the site by its **public** IP, so the source in IIS matches the IP Entra sees. |
| 🔓 3 | Create `C:\inetpub\wwwroot\appsettings.json` with dummy content and request it. IIS doesn't serve unknown extensions like `.env` by default, which is one reason to test with `.json`. |

Events take up to about 15 minutes to arrive. Run the rule query in **Logs** first, then wait for the next scheduled run.
