
# 👤 User Investigation

**On-demand investigation for a single account, from the first phishing email to full takeover.**

Select a user and time range to get a chronological timeline of email, identity and mailbox activity before and after a suspected compromise. Built for speed during active BEC and impersonation investigations.

---

## Why this exists

Account compromise plays out across Entra ID sign-in logs, directory audit logs, and Exchange mailbox activity — three different tables with three different schemas. Reconstructing what an attacker did to an account means querying all of them and lining up timestamps manually.

This unifies them into one timeline. Use it when a user is named in a phishing report, is targeted by a spray or phishing campaign, appears in a risky sign-in alert, or is identified during a device investigation.

---

## 🧭 Phases

Every row also gets a **Phase**, so the same view works before, during and after a compromise:

| Phase | Covers |
| --- | --- |
| 1️⃣ Pre-Compromise | Phishing received, blocked phishing clicks, failed brute force and spray, MFA fatigue |
| 2️⃣ Initial Access | Risky or unusual sign-ins, sign-ins from malicious IPs, clicked-through phishing, successful spray, token replay |
| 3️⃣ Post-Compromise | MFA and password changes, roles, OAuth consent, app credentials, mailbox rules and delegation, export, mass delete, download and sharing, device logons |
| 🚨 Alert | Security alerts naming the user |

Filter on **Phase** to answer "was the user only targeted?" versus "did someone get in, and what did they do?".

---

## What it searches for

| Category | Signals |
| --- | --- |
| **Phishing Received** | Phish and malware emails delivered to or blocked for the user, with sender, subject and where they landed |
| **MFA Changes** | New authentication methods registered, device registration |
| **Account Takeover** | MFA methods deleted, password resets, device unregistration |
| **Mailbox Rules** | Inbox and transport rules with forwarding, redirect, or blind-copy targets |
| **Risky Sign-ins** | Entra ID risk detections, `atRisk` and `confirmedCompromised` states |
| **Rare Geography** | Sign-ins from countries unusual **for this specific user**, not globally |
| **Malicious IPs** | Logons correlated against threat-intel feeds (botnet C2, Tor exit nodes) |
| **OAuth Consent** | Application permission grants — persistent access that survives a password reset |
| **Mailbox Export** | eDiscovery, compliance search, and bulk mail export operations |
| **Phishing Click** | Risky or blocked Safe Links clicks, including the 7 days before the range, with the email sender and subject |
| **Token Replay** | One sign-in session used from several IPs or countries, the sign of a stolen session cookie (AiTM) |
| **Containment Status** | Whether sessions were revoked, the password and MFA reset by an admin, and the account disabled ([panel](#-containment-status-panel)) |
| **Sign-In Activity** | Every interactive and non-interactive sign-in, flagged against the user's 30-day baseline ([panel](#-sign-in-activity-panel)) |

---

## KQL

```kql
// ============================================================
// USER INVESTIGATION - Workbook (Parameterized, Risk-Scored, Phase-Tagged)
// Parameters: {UserPrincipalName} (empty = all users), {TimeRange}
// ============================================================
let TargetUser = tolower(trim(" ", "{UserPrincipalName}"));
let UserLocal  = tostring(split(TargetUser, "@")[0]);
let UserDomain = tostring(split(TargetUser, "@")[1]);
let LegacyClients = dynamic([
    "Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Other clients",
    "Exchange Web Services", "AutoDiscover", "Offline Address Book",
    "Outlook Anywhere (RPC over HTTP)", "Exchange Online PowerShell"
]);
let PrivRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Exchange Administrator", "Security Administrator", "Application Administrator",
    "Cloud Application Administrator", "User Administrator", "Authentication Administrator",
    "SharePoint Administrator", "Conditional Access Administrator", "Intune Administrator"
]);
let RiskyScopes = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite", "Files.ReadWrite.All",
    "Files.Read.All", "Sites.ReadWrite.All", "full_access_as_user", "EWS.AccessAsUser.All",
    "Directory.ReadWrite.All", "User.ReadWrite.All", "Contacts.Read"
]);
let HighRiskDetections = dynamic([
    "anomalousToken", "tokenIssuerAnomaly", "attackerinTheMiddle", "maliciousIPAddress",
    "leakedCredentials", "passwordSpray", "mcasSuspiciousInboxManipulationRules",
    "investigationsThreatIntelligence", "suspiciousAPITraffic", "mcasImpossibleTravel"
]);
// ---------- Shared sources ----------
let Sign = SigninLogs
    | where TimeGenerated {TimeRange}
    | where isempty(TargetUser) or tolower(UserPrincipalName) == TargetUser
    | extend Country = tostring(LocationDetails.countryOrRegion),
             Loc = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion)),
             Lat = todouble(LocationDetails.geoCoordinates.latitude),
             Lon = todouble(LocationDetails.geoCoordinates.longitude),
             Dev = tostring(DeviceDetail.displayName),
             OSBrowser = strcat(tostring(DeviceDetail.operatingSystem), " | ", tostring(split(tostring(DeviceDetail.browser), " ")[0]));
let OkSign = Sign | where ResultType == "0";
let Baseline = SigninLogs
    | where TimeGenerated between (ago(30d) .. {TimeRange:start})
    | where isempty(TargetUser) or tolower(UserPrincipalName) == TargetUser
    | where ResultType == "0"
    | summarize BaseCountries = make_set(tostring(LocationDetails.countryOrRegion), 200),
                BaseOSBrowser = make_set(strcat(tostring(DeviceDetail.operatingSystem), " | ", tostring(split(tostring(DeviceDetail.browser), " ")[0])), 200)
        by UserPrincipalName;
let Audit = AuditLogs
    | where TimeGenerated {TimeRange}
    | extend Target  = tolower(tostring(TargetResources[0].userPrincipalName)),
             Actor   = tolower(coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))),
             ActorIP = tostring(InitiatedBy.user.ipAddress)
    | where isempty(TargetUser) or Target == TargetUser or Actor == TargetUser;
let Office = OfficeActivity
    | where TimeGenerated {TimeRange}
    | extend P = strcat(tostring(Parameters), " ", tostring(column_ifexists("OperationProperties", ""))),
             CleanIP = coalesce(extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP), ClientIP)
    | where isempty(TargetUser) or tolower(UserId) == TargetUser or P has TargetUser;
let TI = union isfuzzy=true
    (ThreatIntelligenceIndicator | where TimeGenerated > ago(30d) | where isnotempty(NetworkIP)
        | summarize TIDesc = take_any(strcat(ThreatType, " ", Description)) by IP = NetworkIP),
    (ThreatIntelIndicators | where TimeGenerated > ago(30d) | where ObservableKey has "ipv4"
        | summarize TIDesc = take_any(tostring(Data.description)) by IP = ObservableValue)
    | summarize TIDesc = take_any(TIDesc) by IP;
// ============================================================
union isfuzzy=true
// ---------- 🚨 Risky Sign-in ----------
(Sign
    | where RiskLevelDuringSignIn in ("medium", "high") or RiskState == "atRisk"
    | project TimeGenerated, Signal = "🚨 Risky Sign-in",
        RiskScore = toint(iff(RiskLevelDuringSignIn == "high", 9, 7) - iff(ResultType == "0", 0, 2)),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = Dev, App = AppDisplayName,
        Detail = strcat("Risk: ", RiskLevelDuringSignIn, " | State: ", RiskState, " | Events: ", tostring(RiskEventTypes_V2),
                        " | Result: ", iff(ResultType == "0", "Success", ResultDescription)),
        UserAgent, EventCount = tolong(1)),
// ---------- 🛡️ Identity Protection Detection ----------
(AADUserRiskEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetUser) or tolower(UserPrincipalName) == TargetUser
    | extend L = parse_json(tostring(Location))
    | project TimeGenerated, Signal = "🛡️ Identity Protection Detection",
        RiskScore = toint(case(RiskEventType in (HighRiskDetections), 9, RiskLevel == "high", 8, RiskLevel == "medium", 6, 4)),
        Account = UserPrincipalName, IPAddress = IpAddress,
        Location = strcat(tostring(L.city), ", ", tostring(L.countryOrRegion)), DeviceName = "", App = Source,
        Detail = strcat(RiskEventType, " | Level: ", RiskLevel, " | State: ", RiskState, " | ", DetectionTimingType),
        UserAgent = "", EventCount = tolong(1)),
// ---------- 🔑 Brute Force / Spray ----------
(Sign
    | where ResultType in ("50126", "50053", "50034", "50056")
    | summarize Failures = count(), FirstFail = min(TimeGenerated), Codes = make_set(ResultType, 10)
        by UserPrincipalName, IPAddress, Loc, bin(TimeGenerated, 1h)
    | where Failures >= 5
    | join kind=leftouter (OkSign | summarize SuccessTime = min(TimeGenerated), SuccessApp = take_any(AppDisplayName) by UserPrincipalName, IPAddress)
        on UserPrincipalName, IPAddress
    | extend Succeeded = isnotempty(SuccessTime) and SuccessTime >= FirstFail
    | project TimeGenerated, Signal = "🔑 Brute Force / Spray", RiskScore = toint(iff(Succeeded, 9, 6)),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = "", App = iff(Succeeded, SuccessApp, ""),
        Detail = strcat(Failures, " failed logons (", strcat_array(Codes, ","), ")",
                        iff(Succeeded, strcat(" -> SUCCESS from same IP at ", format_datetime(SuccessTime, "yyyy-MM-dd HH:mm")), "")),
        UserAgent = "", EventCount = tolong(Failures)),
// ---------- 📲 MFA Fatigue ----------
(Sign
    | where ResultType == "500121"
    | summarize Denied = count() by UserPrincipalName, IPAddress, Loc, AppDisplayName, bin(TimeGenerated, 1h)
    | where Denied >= 3
    | project TimeGenerated, Signal = "📲 MFA Fatigue", RiskScore = toint(iff(Denied >= 10, 8, 7)),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = "", App = AppDisplayName,
        Detail = strcat(Denied, " MFA challenges failed/denied in 1h"), UserAgent = "", EventCount = tolong(Denied)),
// ---------- ✈️ Impossible Travel ----------
(OkSign
    | where isnotempty(Lat) and isnotempty(Lon)
    | project TimeGenerated, UserPrincipalName, IPAddress, Loc, Lat, Lon, AppDisplayName, UserAgent, Dev
    | sort by UserPrincipalName asc, TimeGenerated asc
    | extend PUser = prev(UserPrincipalName), PTime = prev(TimeGenerated), PLat = prev(Lat), PLon = prev(Lon), PIP = prev(IPAddress), PLoc = prev(Loc)
    | where PUser == UserPrincipalName and PIP != IPAddress
    | extend Km = geo_distance_2points(PLon, PLat, Lon, Lat) / 1000.0,
             Mins = datetime_diff("minute", TimeGenerated, PTime)
    | extend Kmh = Km / max_of(todouble(Mins) / 60.0, 0.05)
    | where Km > 500 and Kmh > 900
    | project TimeGenerated, Signal = "✈️ Impossible Travel", RiskScore = toint(8),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = Dev, App = AppDisplayName,
        Detail = strcat(PLoc, " (", PIP, ") -> ", Loc, " (", IPAddress, ") | ", round(Km), " km in ", Mins, " min"),
        UserAgent, EventCount = tolong(1)),
// ---------- 🌍 New Country Sign-in (vs 30d baseline) ----------
(OkSign
    | join kind=inner Baseline on UserPrincipalName
    | where isnotempty(Country) and not(set_has_element(BaseCountries, Country))
    | project TimeGenerated, Signal = "🌍 New Country Sign-in", RiskScore = toint(7),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = Dev, App = AppDisplayName,
        Detail = strcat("First sign-in from ", Country, " in 30 days | Known: ", strcat_array(BaseCountries, ", ")),
        UserAgent, EventCount = tolong(1)),
// ---------- 💻 New OS / Browser (vs 30d baseline) ----------
(OkSign
    | join kind=inner Baseline on UserPrincipalName
    | where OSBrowser != " | " and not(set_has_element(BaseOSBrowser, OSBrowser))
    | project TimeGenerated, Signal = "💻 New OS / Browser", RiskScore = toint(4),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = Dev, App = AppDisplayName,
        Detail = strcat("New client: ", OSBrowser), UserAgent, EventCount = tolong(1)),
// ---------- 🕰️ Legacy Auth ----------
(Sign
    | where ClientAppUsed in (LegacyClients)
    | project TimeGenerated, Signal = "🕰️ Legacy Auth", RiskScore = toint(iff(ResultType == "0", 6, 3)),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = Dev, App = AppDisplayName,
        Detail = strcat("Client: ", ClientAppUsed, " | Result: ", iff(ResultType == "0", "Success", ResultDescription)),
        UserAgent, EventCount = tolong(1)),
// ---------- ☠️ Sign-in from TI IP ----------
(Sign
    | join kind=inner TI on $left.IPAddress == $right.IP
    | project TimeGenerated, Signal = "☠️ Sign-in from Malicious IP", RiskScore = toint(iff(ResultType == "0", 9, 7)),
        Account = UserPrincipalName, IPAddress, Location = Loc, DeviceName = Dev, App = AppDisplayName,
        Detail = strcat("TI: ", TIDesc, " | Result: ", iff(ResultType == "0", "Success", ResultDescription)),
        UserAgent, EventCount = tolong(1)),
// ---------- 📱 MFA / Auth Method Change ----------
(Audit
    | where OperationName has_any ("security info", "authentication method", "StrongAuthentication")
        or (OperationName == "Update user" and tostring(TargetResources) has "StrongAuthentication")
    | project TimeGenerated, Signal = "📱 MFA / Auth Method Change",
        RiskScore = toint(iff(OperationName has_any ("deleted", "delete", "removed"), 8, 7)),
        Account = coalesce(Target, Actor), IPAddress = ActorIP, Location = "", DeviceName = "", App = LoggedByService,
        Detail = strcat(OperationName, " | By: ", Actor, " | Result: ", Result), UserAgent = "", EventCount = tolong(1)),
// ---------- 🔐 Password Reset / Change ----------
(Audit
    | where OperationName has "password" and OperationName !has "security info"
    | project TimeGenerated, Signal = "🔐 Password Reset / Change",
        RiskScore = toint(iff(isnotempty(Target) and Actor != Target, 6, 4)),
        Account = coalesce(Target, Actor), IPAddress = ActorIP, Location = "", DeviceName = "", App = LoggedByService,
        Detail = strcat(OperationName, " | By: ", Actor, " | Result: ", Result), UserAgent = "", EventCount = tolong(1)),
// ---------- 👑 Role Assignment ----------
(Audit
    | where OperationName has "member to role"
    | mv-apply mp = TargetResources[0].modifiedProperties on (
        summarize Role = take_anyif(trim(@'"', tostring(mp.newValue)), tostring(mp.displayName) == "Role.DisplayName"))
    | project TimeGenerated, Signal = "👑 Role Assignment", RiskScore = toint(iff(Role in (PrivRoles), 9, 7)),
        Account = Target, IPAddress = ActorIP, Location = "", DeviceName = "", App = LoggedByService,
        Detail = strcat(OperationName, " | Role: ", Role, " | By: ", Actor), UserAgent = "", EventCount = tolong(1)),
// ---------- 🔓 OAuth Consent ----------
(Audit
    | where OperationName in ("Consent to application", "Add delegated permission grant", "Add app role assignment grant to user")
    | mv-apply mp = TargetResources[0].modifiedProperties on (
        summarize Perms = take_anyif(tostring(mp.newValue), tostring(mp.displayName) in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope")),
                  IsAdmin = take_anyif(tostring(mp.newValue), tostring(mp.displayName) == "ConsentContext.IsAdminConsent"))
    | project TimeGenerated, Signal = "🔓 OAuth Consent", RiskScore = toint(iff(Perms has_any (RiskyScopes), 9, 7)),
        Account = Actor, IPAddress = ActorIP, Location = "", DeviceName = "", App = tostring(TargetResources[0].displayName),
        Detail = strcat(OperationName, " | AdminConsent: ", IsAdmin, " | Scopes: ", substring(Perms, 0, 300)), UserAgent = "", EventCount = tolong(1)),
// ---------- 🧩 App Credential / Owner Added ----------
(Audit
    | where OperationName has_any ("Add service principal credentials", "Certificates and secrets management", "Add owner to application", "Add owner to service principal")
    | project TimeGenerated, Signal = "🧩 App Credential / Owner Added", RiskScore = toint(8),
        Account = Actor, IPAddress = ActorIP, Location = "", DeviceName = "", App = tostring(TargetResources[0].displayName),
        Detail = strcat(OperationName, " | Target: ", tostring(TargetResources[0].displayName)), UserAgent = "", EventCount = tolong(1)),
// ---------- 📧 Inbox Rule / Forwarding ----------
(Office
    | where Operation in~ ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule", "UpdateInboxRules", "Set-Mailbox")
    | where Operation !~ "Set-Mailbox" or P has_any ("ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward")
    | extend Fwd = P has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress", "ForwardingAddress"),
             Del = P has_any ("DeleteMessage", "SoftDeleteMessage"),
             Hide = P has_any ("RSS", "Conversation History", "Archive", "Junk"),
             MarkRead = P has "MarkAsRead"
    | project TimeGenerated, Signal = "📧 Inbox Rule / Forwarding",
        RiskScore = toint(min_of(10, 5 + iff(Fwd, 3, 0) + iff(Del, 2, 0) + iff(Hide, 2, 0))),
        Account = UserId, IPAddress = CleanIP, Location = "", DeviceName = "", App = "Exchange",
        Detail = strcat(Operation, " | ", iff(Fwd, "FORWARD ", ""), iff(Del, "DELETE ", ""), iff(Hide, "HIDE-FOLDER ", ""),
                        iff(MarkRead, "MARK-READ ", ""), "| ", substring(P, 0, 300)),
        UserAgent = "", EventCount = tolong(1)),
// ---------- 👥 Mailbox Delegation / SendAs ----------
(Office
    | where Operation in~ ("Add-MailboxPermission", "Add-RecipientPermission", "Add-MailboxFolderPermission", "Set-MailboxFolderPermission", "Add-ADPermission")
    | project TimeGenerated, Signal = "👥 Mailbox Delegation / SendAs",
        RiskScore = toint(iff(P has_any ("FullAccess", "SendAs"), 7, 6)),
        Account = UserId, IPAddress = CleanIP, Location = "", DeviceName = "", App = "Exchange",
        Detail = strcat(Operation, " | ", substring(P, 0, 300)), UserAgent = "", EventCount = tolong(1)),
// ---------- 📦 Mailbox Export / Content Search ----------
(Office
    | where Operation in~ ("New-MailboxExportRequest", "New-ComplianceSearch", "Start-ComplianceSearch", "New-ComplianceSearchAction", "New-MailboxSearch", "Search-Mailbox")
    | project TimeGenerated, Signal = "📦 Mailbox Export / Search", RiskScore = toint(8),
        Account = UserId, IPAddress = CleanIP, Location = "", DeviceName = "", App = "Exchange",
        Detail = strcat(Operation, " | ", substring(P, 0, 300)), UserAgent = "", EventCount = tolong(1)),
// ---------- 🗑️ Mass Mail Delete ----------
(Office
    | where Operation in ("SoftDelete", "HardDelete", "MoveToDeletedItems")
    | summarize Cnt = count(), Ops = make_set(Operation, 3) by UserId, CleanIP, bin(TimeGenerated, 1h)
    | where Cnt >= 50
    | project TimeGenerated, Signal = "🗑️ Mass Mail Delete", RiskScore = toint(iff(set_has_element(Ops, "HardDelete"), 7, 6)),
        Account = UserId, IPAddress = CleanIP, Location = "", DeviceName = "", App = "Exchange",
        Detail = strcat(Cnt, " delete operations in 1h (", strcat_array(Ops, ","), ")"), UserAgent = "", EventCount = tolong(Cnt)),
// ---------- ☁️ Mass SharePoint / OneDrive Download ----------
(Office
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
    | summarize Files = dcount(OfficeObjectId), Cnt = count(), Sample = make_set(SourceFileName, 5) by UserId, CleanIP, bin(TimeGenerated, 1h)
    | where Files >= 50
    | project TimeGenerated, Signal = "☁️ Mass Cloud Download", RiskScore = toint(iff(Files >= 200, 8, 6)),
        Account = UserId, IPAddress = CleanIP, Location = "", DeviceName = "", App = "SharePoint/OneDrive",
        Detail = strcat(Files, " files in 1h | e.g. ", strcat_array(Sample, ", ")), UserAgent = "", EventCount = tolong(Cnt)),
// ---------- 🔗 External / Anonymous Sharing ----------
(Office
    | where Operation in ("AnonymousLinkCreated", "SharingInvitationCreated", "SecureLinkCreated", "AddedToSecureLink")
    | extend TType = tostring(column_ifexists("TargetUserOrGroupType", "")), TName = tostring(column_ifexists("TargetUserOrGroupName", ""))
    | where Operation == "AnonymousLinkCreated" or TType =~ "Guest" or TName has "#ext#"
    | summarize Cnt = count(), Sample = make_set(SourceFileName, 5), To = make_set(TName, 5) by UserId, CleanIP, Operation, bin(TimeGenerated, 1h)
    | project TimeGenerated, Signal = "🔗 External / Anonymous Sharing", RiskScore = toint(iff(Operation == "AnonymousLinkCreated", 6, 5)),
        Account = UserId, IPAddress = CleanIP, Location = "", DeviceName = "", App = "SharePoint/OneDrive",
        Detail = strcat(Operation, " x", Cnt, " | Files: ", strcat_array(Sample, ", "), " | To: ", strcat_array(To, ", ")),
        UserAgent = "", EventCount = tolong(Cnt)),
// ---------- 🖥️ Device Logons by User ----------
(DeviceLogonEvents
    | where TimeGenerated {TimeRange}
    | where isnotempty(UserLocal) and tolower(AccountName) == UserLocal
    | summarize Success = countif(ActionType == "LogonSuccess"), Fail = countif(ActionType == "LogonFailed")
        by DeviceName, LogonType, RemoteIP, RemoteIPType, AccountDomain, AccountName, bin(TimeGenerated, 1h)
    | extend RiskScore = toint(case(RemoteIPType == "Public" and Success > 0, 7, Fail >= 10, 6, LogonType == "RemoteInteractive", 4, 2))
    | project TimeGenerated, Signal = "🖥️ Device Logon", RiskScore,
        Account = strcat(AccountDomain, "\\", AccountName), IPAddress = RemoteIP, Location = RemoteIPType, DeviceName,
        App = LogonType, Detail = strcat(LogonType, " | Success: ", Success, " | Failed: ", Fail),
        UserAgent = "", EventCount = tolong(Success + Fail)),
// ---------- 📨 Phishing Received ----------
(EmailEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetUser) or tolower(RecipientEmailAddress) == TargetUser
    | where ThreatTypes has_any ("Phish", "Malware")
    | where isnotempty(TargetUser) or DeliveryAction == "Delivered"   // all users: only what reached a mailbox
    | project TimeGenerated, Signal = "📨 Phishing Received",
        RiskScore = toint(case(DeliveryAction == "Delivered" and DeliveryLocation has "Inbox", 7,
                               DeliveryAction == "Delivered", 5, 3)),
        Account = RecipientEmailAddress, IPAddress = SenderIPv4, Location = "", DeviceName = "", App = "Exchange Online",
        Detail = strcat(DeliveryAction, " to ", DeliveryLocation, " | ", ThreatTypes, " | From: ", SenderFromAddress,
                        " | ", Subject),
        UserAgent = "", EventCount = tolong(1)),
// ---------- 🎣 Phishing Click (root cause, includes 7 days before the range) ----------
(UrlClickEvents
    | where TimeGenerated between (datetime_add("day", -7, {TimeRange:start}) .. {TimeRange:end})
    | where isempty(TargetUser) or tolower(AccountUpn) == TargetUser
    | where isnotempty(ThreatTypes) or IsClickedThrough == true or ActionType has "Blocked"
    | lookup kind=leftouter (EmailEvents
        | where TimeGenerated > ago(30d)
        | where isempty(TargetUser) or tolower(RecipientEmailAddress) == TargetUser
        | summarize SenderFromAddress = take_any(SenderFromAddress), Subject = take_any(Subject) by NetworkMessageId)
        on NetworkMessageId
    | project TimeGenerated, Signal = "🎣 Phishing Click",
        RiskScore = toint(case(IsClickedThrough == true, 9, ActionType == "ClickAllowed" and isnotempty(ThreatTypes), 9, 6)),
        Account = AccountUpn, IPAddress, Location = "", DeviceName = "", App = Workload,
        Detail = strcat(ActionType, iff(IsClickedThrough == true, " (clicked through warning)", ""), " | ", Url,
                        iff(isnotempty(ThreatTypes), strcat(" | Threats: ", ThreatTypes), ""),
                        iff(isnotempty(SenderFromAddress), strcat(" | From: ", SenderFromAddress, " | ", Subject), "")),
        UserAgent = "", EventCount = tolong(1)),
// ---------- 🍪 Token Replay (one session, many IPs or countries) ----------
(union isfuzzy=true
    (SigninLogs | where TimeGenerated {TimeRange} | extend Loc = LocationDetails),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated {TimeRange} | extend Loc = todynamic(LocationDetails))
    | where isempty(TargetUser) or tolower(UserPrincipalName) == TargetUser
    | where ResultType == "0"
    | extend Sid = tostring(column_ifexists("SessionId", "")), Country = tostring(Loc.countryOrRegion)
    | where isnotempty(Sid)
    | summarize IPs = dcount(IPAddress), Countries = dcount(Country), IPList = make_set(IPAddress, 10),
                CountryList = make_set(Country, 5), Apps = make_set(AppDisplayName, 5), First = min(TimeGenerated), Cnt = count()
        by UserPrincipalName, Sid
    | where Countries >= 2 or IPs >= 4
    | project TimeGenerated = First, Signal = "🍪 Token Replay", RiskScore = toint(iff(Countries >= 2, 9, 6)),
        Account = UserPrincipalName, IPAddress = tostring(IPList[0]), Location = strcat_array(CountryList, ", "),
        DeviceName = "", App = strcat_array(Apps, ", "),
        Detail = strcat("Session ", Sid, " used from ", IPs, " IPs in ", Countries, " countries: ", strcat_array(IPList, ", ")),
        UserAgent = "", EventCount = tolong(Cnt)),
// ---------- 🚩 Security Alerts for User ----------
(SecurityAlert
    | where TimeGenerated {TimeRange}
    | where isempty(TargetUser) or tolower(Entities) has TargetUser or tolower(Entities) contains strcat('"name":"', UserLocal, '"')
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project TimeGenerated, Signal = "🚩 Security Alert",
        RiskScore = toint(case(AlertSeverity == "High", 9, AlertSeverity == "Medium", 7, AlertSeverity == "Low", 5, 3)),
        Account = iff(isempty(TargetUser), CompromisedEntity, TargetUser),
        IPAddress = extract(@'"Address":"([^"]+)"', 1, Entities), Location = "",
        DeviceName = extract(@'"HostName":"([^"]+)"', 1, Entities), App = ProductName,
        Detail = strcat(AlertName, " | ", Status, " | ", substring(Description, 0, 200)), UserAgent = "", EventCount = tolong(1))
// ============================================================
| summarize Hits = sum(EventCount)
    by TimeGenerated = bin(TimeGenerated, 1m), Signal, RiskScore, Account, IPAddress, Location, DeviceName, App, Detail, UserAgent
| extend Severity = case(RiskScore >= 9, "Critical", RiskScore >= 7, "High", RiskScore >= 5, "Medium", RiskScore >= 3, "Low", "Informational")
| extend Phase = case(
    Signal startswith "🚩", "🚨 Alert",
    Signal has "Phishing Received" or Signal has "MFA Fatigue"
        or (Signal has "Brute Force" and RiskScore < 9)
        or (Signal has "Phishing Click" and RiskScore < 9), "1️⃣ Pre-Compromise",
    Signal matches regex "Phishing Click|Brute Force|Risky Sign-in|Identity Protection|Impossible Travel|New Country|New OS|Legacy Auth|Malicious IP|Token Replay", "2️⃣ Initial Access",
    "3️⃣ Post-Compromise")
| extend IPs  = extract_all(@"(\b\d+\.\d+\.\d+\.\d+\b)", strcat(IPAddress, " ", Detail)),
         Doms = extract_all(@"@([A-Za-z0-9.-]+\.[A-Za-z]+)", Detail)
| extend IPs = iff(isnull(IPs), dynamic([]), IPs), Doms = iff(isnull(Doms), dynamic([]), Doms)
| extend IOCs = strcat_array(set_difference(set_union(IPs, Doms), pack_array(UserDomain)), ", ")
| project TimeGenerated, Severity, RiskScore, Phase, Hits, Signal, Account, IPAddress, Location, DeviceName, App, Detail, IOCs, UserAgent
| sort by RiskScore desc, TimeGenerated desc
```

---

## 🔐 Sign-In Activity Panel

A second grid panel that lists every sign-in for the selected user, interactive and non-interactive, grouped by hour, IP, app and device. Each row is flagged against the user's own 30-day baseline, so new countries, new IPs and new devices stand out.

**Visualization:** Grid  ·  **Parameters:** `{UserPrincipalName}` (required), `{TimeRange}`

| Flag | Meaning |
| --- | --- |
| 🌍 New Country | Successful sign-in from a country not seen in the last 30 days |
| 🆕 New IP | IP not seen in the user's successful sign-ins in the last 30 days |
| 💻 New OS/Browser | OS and browser pair not seen before |
| 🧓 Legacy Auth | IMAP, POP, SMTP, ActiveSync or other legacy clients |
| 🚨 Risky | Entra ID rated the sign-in medium or high risk |
| 📲 MFA Denied | MFA challenge failed or was denied |
| 🔓 Single-Factor | Successful sign-in that only needed a password |

```kql
let TargetUser = tolower(trim(" ", "{UserPrincipalName}"));
let LegacyClients = dynamic([
    "Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Other clients",
    "Exchange Web Services", "AutoDiscover", "Offline Address Book",
    "Outlook Anywhere (RPC over HTTP)", "Exchange Online PowerShell"]);
let Base = SigninLogs
    | where TimeGenerated between (ago(30d) .. {TimeRange:start})
    | where tolower(UserPrincipalName) == TargetUser and ResultType == "0";
let BaseCountries = toscalar(Base | summarize make_set(tostring(LocationDetails.countryOrRegion), 200));
let BaseIPs = toscalar(Base | summarize make_set(IPAddress, 1000));
let BaseOSBrowser = toscalar(Base | summarize make_set(strcat(tostring(DeviceDetail.operatingSystem), " | ",
    tostring(split(tostring(DeviceDetail.browser), " ")[0])), 200));
union isfuzzy=true
    (SigninLogs
        | where TimeGenerated {TimeRange}
        | where tolower(UserPrincipalName) == TargetUser
        | extend SignInType = "Interactive", Loc = LocationDetails, Dev = DeviceDetail),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated {TimeRange}
        | where tolower(UserPrincipalName) == TargetUser
        | extend SignInType = "Non-interactive", Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail))
| extend Country = tostring(Loc.countryOrRegion),
         Location = strcat(tostring(Loc.city), ", ", tostring(Loc.countryOrRegion)),
         OSBrowser = strcat(tostring(Dev.operatingSystem), " | ", tostring(split(tostring(Dev.browser), " ")[0])),
         DeviceName = tostring(Dev.displayName),
         Compliant = tostring(Dev.isCompliant),
         Success = ResultType == "0"
| extend Flags = strcat_array(array_concat(
    iff(Success and isnotempty(Country) and not(set_has_element(BaseCountries, Country)), dynamic(["🌍 New Country"]), dynamic([])),
    iff(Success and not(set_has_element(BaseIPs, IPAddress)), dynamic(["🆕 New IP"]), dynamic([])),
    iff(Success and not(set_has_element(BaseOSBrowser, OSBrowser)), dynamic(["💻 New OS/Browser"]), dynamic([])),
    iff(ClientAppUsed in (LegacyClients), dynamic(["🧓 Legacy Auth"]), dynamic([])),
    iff(RiskLevelDuringSignIn in ("medium", "high"), dynamic(["🚨 Risky"]), dynamic([])),
    iff(ResultType == "500121", dynamic(["📲 MFA Denied"]), dynamic([])),
    iff(Success and AuthenticationRequirement == "singleFactorAuthentication" and SignInType == "Interactive", dynamic(["🔓 Single-Factor"]), dynamic([]))), " ")
| summarize SignIns = count(),
            Failures = countif(not(Success)),
            Results = make_set(iff(Success, "Success", strcat(ResultType, " ", ResultDescription)), 5),
            Flags = take_any(Flags),
            Risk = take_any(RiskLevelDuringSignIn),
            CAStatus = take_any(ConditionalAccessStatus),
            UserAgent = take_any(UserAgent)
         by TimeGenerated = bin(TimeGenerated, 1h), SignInType, IPAddress, Location, AppDisplayName, ClientAppUsed,
            OSBrowser, DeviceName, Compliant
| extend RiskScore = toint(
    iff(Flags has "Risky", 3, 0) + iff(Flags has "New Country", 3, 0) + iff(Flags has "Legacy Auth", 2, 0)
    + iff(Flags has "MFA Denied", 2, 0) + iff(Flags has "New IP", 1, 0) + iff(Flags has "New OS", 1, 0)
    + iff(Flags has "Single-Factor", 1, 0))
| extend Severity = case(RiskScore >= 6, "🔴 High", RiskScore >= 3, "🟠 Medium", RiskScore >= 1, "🟡 Low", "⚪ Normal")
| sort by TimeGenerated desc
| project TimeGenerated, Severity, Flags, SignInType, IPAddress, Location, AppDisplayName, ClientAppUsed, SignIns, Failures,
          Results, OSBrowser, DeviceName, Compliant, Risk, CAStatus, UserAgent
```

**💡 Tips**

- Sort by **Severity** to surface flagged rows first, or by **TimeGenerated** to read the timeline.
- Non-interactive sign-ins are token refreshes from apps already signed in. A new IP there after a password reset points to a stolen token or session.
- The baseline covers only the 30 days **before** the time range, so the attacker's own sign-ins don't count as normal.

---

## 🧹 Containment Status Panel

A tile row for the selected user that shows whether the account has been contained. Check it at the end of an investigation, or before closing the incident.

**Visualization:** Tiles (Title: `Metric`, Left: `Status`, Bottom: `When`)  ·  **Parameters:** `{UserPrincipalName}` (required), `{TimeRange}`

```kql
let TargetUser = tolower(trim(" ", "{UserPrincipalName}"));
AuditLogs
| where TimeGenerated {TimeRange}
| where isnotempty(TargetUser)
| extend Target = tolower(tostring(TargetResources[0].userPrincipalName)),
         Actor  = tolower(coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)))
| where Target == TargetUser
| summarize Revoked  = maxif(TimeGenerated, OperationName has_any ("refresh tokens", "sign-in sessions", "Revoke")),
            PwReset  = maxif(TimeGenerated, OperationName has "password" and OperationName !has "security info" and Actor != Target),
            MfaReset = maxif(TimeGenerated, OperationName has "security info" and Actor != Target),
            Disabled = maxif(TimeGenerated, OperationName == "Disable account")
| where isnotempty(TargetUser)
| extend Contained = isnotnull(Revoked) and isnotnull(PwReset)
| extend Rows = pack_array(
    bag_pack("Order", 1, "Metric", "🧹 Contained", "Done", Contained, "When", ""),
    bag_pack("Order", 2, "Metric", "🔒 Sessions Revoked", "Done", isnotnull(Revoked), "When", format_datetime(Revoked, "yyyy-MM-dd HH:mm")),
    bag_pack("Order", 3, "Metric", "🔐 Password Reset by Admin", "Done", isnotnull(PwReset), "When", format_datetime(PwReset, "yyyy-MM-dd HH:mm")),
    bag_pack("Order", 4, "Metric", "📱 MFA Reset by Admin", "Done", isnotnull(MfaReset), "When", format_datetime(MfaReset, "yyyy-MM-dd HH:mm")),
    bag_pack("Order", 5, "Metric", "⛔ Account Disabled", "Done", isnotnull(Disabled), "When", format_datetime(Disabled, "yyyy-MM-dd HH:mm")))
| mv-expand Row = Rows
| extend Order = toint(Row.Order), Metric = tostring(Row.Metric), Done = tobool(Row.Done), When = tostring(Row.When)
| extend Status = case(Order == 1 and Done, "✅ Yes", Order == 1, "❌ No", Order == 5 and not(Done), "➖ No", Done, "✅ Done", "❌ Not done")
| sort by Order asc
| project Metric, Status, When
```

**💡 Notes**

- **Contained** means sessions were revoked **and** an admin reset the password. Disabling the account is optional, so it shows ➖ instead of ❌.
- Only admin actions count. A password change by the user (or an attacker signed in as the user) doesn't mark the account as contained.
