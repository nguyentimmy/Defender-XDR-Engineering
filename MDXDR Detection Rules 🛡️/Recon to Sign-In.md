# 🔗 Recon to Sign-In

An IP that requested sensitive web paths in the last 24 hours, then signed in (or tried to) to Entra ID. This is the harvest-then-log-in chain: an agent finds credentials in an exposed file and uses them.

> 📌 Part of the **AI & Autonomous Threats** detection set. Built from workbook panel 13 (Recon to Sign-In). This is a Microsoft Sentinel scheduled analytic rule.

| | |
|---|---|
| 🗂️ Data sources | IIS logs (`W3CIISLog`) through Azure Monitor Agent, plus Entra ID sign-in logs (`SigninLogs`, `AADNonInteractiveUserSignInLogs`) |
| 🔴 Default severity | High (overridden per alert by the `Severity` column) |
| ⏱️ Schedule | Every 1 hour, looking back 1 day |

---

## 🔎 Query

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

## ⚙️ Rule Settings

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

## 🛠️ Tuning

- Add corporate egress IPs, VPN gateways and approved scanners to `Allowlist`. Otherwise a scanner and a real user behind the same NAT look like this attack.
- If IIS sits behind Application Gateway or a load balancer, `cIP` is the proxy's address. Log `X-Forwarded-For` as a custom IIS field and use it instead of `cIP`.
- **🍯 Honeytoken pairing:** serve a decoy `/.env` containing honeytoken credentials. A successful or valid-password row for the honeytoken account is a confirmed attacker. Add an automation rule that runs the Honeytoken Isolation playbook when the account is a honeytoken.

---

## 🧭 Avoiding Duplicate Alerts

The rule runs every hour but looks back further, so it can match probes from the last day with new sign-ins. To stop the same activity alerting every hour, the query only returns results when new data arrived in the last hour (`ingestion_time() > ago(1h)`). This also catches events that were ingested late, which a plain `TimeGenerated` filter would miss.

---

## 🛠️ Creating the Rule in Sentinel

1. Go to **Microsoft Sentinel > Analytics > Create > Scheduled query rule**. In the Defender portal: **Microsoft Sentinel > Configuration > Analytics**.
2. **General:** enter the name and severity from Rule Settings.
3. **Set rule logic:** paste the query. Map entities, add custom details, and set the alert name format and severity column under **Alert details**. Set the schedule and threshold.
4. **Incident settings:** keep incident creation on and set alert grouping from the table.
5. **Automated response:** attach automation rules if you want (for example the Honeytoken Isolation playbook).
6. **Review + create.**

---

## 🧪 Lab Testing

Request `http://<windows-vm public IP>/.env` from Kali, then sign in to the Microsoft 365 portal from Kali with a test account (wrong password is fine). Kali must reach the site by its **public** IP, so the source in IIS matches the IP Entra sees.

Events take up to about 15 minutes to arrive. Run the query in **Logs** first, then wait for the next scheduled run.
